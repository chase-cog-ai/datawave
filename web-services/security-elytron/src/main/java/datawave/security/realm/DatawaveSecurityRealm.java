package datawave.security.realm;

import java.security.Key;
import java.security.KeyStoreException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import javax.inject.Inject;
import javax.net.ssl.X509KeyManager;

import org.apache.log4j.Logger;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.realm.CacheableSecurityRealm;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;

import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.guava.GuavaModule;
import com.fasterxml.jackson.module.jaxb.JaxbAnnotationModule;
import com.google.common.base.Preconditions;

import datawave.configuration.spring.BeanProvider;
import datawave.security.SSLContextInfo;
import datawave.security.authorization.DatawavePrincipal;
import datawave.security.authorization.DatawaveUser;
import datawave.security.authorization.DatawaveUserService;
import datawave.security.authorization.JWTTokenHandler;
import datawave.security.cert.DatawaveCertVerifier;
import datawave.security.cert.X509CertificateVerifier;
import datawave.security.evidence.EvidenceIdentity;
import datawave.security.evidence.EvidenceIdentityProvider;
import datawave.security.evidence.JWTEvidenceIdentityProvider;
import datawave.security.evidence.ProxiedX509CertificateEvidenceIdentityProvider;
import datawave.security.evidence.TrustedHeaderEvidenceIdentityProvider;

public class DatawaveSecurityRealm implements CacheableSecurityRealm {

    private static final Logger log = Logger.getLogger(DatawaveSecurityRealm.class);

    /**
     * The user service.
     */
    private DatawaveUserService userService;

    /**
     * The SSL context info.
     */
    private SSLContextInfo sslContextInfo;

    /**
     * The configuration properties. This is updated every time {@link #initialize(Map)} is called.
     */
    private DatawaveSecurityRealmConfig config = null;

    /**
     * The configured identity providers. These are established the first time {@link DatawaveSecurityRealm#initializeProviders()} is called.
     */
    private Set<EvidenceIdentityProvider> identityProviders = null;

    /**
     * Whether {@link DatawaveSecurityRealm#initializeProviders()} has ever been called.
     */
    private boolean providersInitialized = false;

    /**
     * Set/inject the user service.
     *
     * @param userService
     *            the user service
     */
    @Inject
    public void setDatawaveUserService(DatawaveUserService userService) {
        this.userService = userService;
    }

    /**
     * Set/inject the {@link SSLContextInfo} t
     *
     * @param sslContextInfo
     *            the SSL context
     */
    @Inject
    public void setSSLContextInfo(SSLContextInfo sslContextInfo) {
        this.sslContextInfo = sslContextInfo;
    }

    /**
     * This method is invoked by the Wildfly Elytron subsystem during the realm's lifecycle to provide configuration parameters. These parameters are typically
     * defined in the Wildfly configuration files, such as jboss .cli files or in the standalone.xml. There is no guarantee that beans will be available for
     * injection at the time that this method is invoked, so any manual injection of beans should be delayed until the first authentication attempt.
     * <p>
     * NOTE: Any configuration parameters passed into here will be parsed and stored, but any configuration requiring the presence of CDI beans will not take
     * effect until the next time either @link #getRealmIdentity(Evidence)} or {@link #getEvidenceVerifySupport(Class, String)}is called.
     * <p>
     *
     * @param config
     *            the configuration parameters
     * @see DatawaveSecurityRealmConfig#fromMap(Map) The list of supported configuration parameters
     */
    public void initialize(Map<String,String> config) {
        if (log.isTraceEnabled()) {
            log.trace("Initializing " + DatawaveSecurityRealm.class.getName() + " with config=" + config);
        }
        // Parse the configuration properties.
        this.config = DatawaveSecurityRealmConfig.fromMap(config);
        // Set this to null to force the identity providers to be reinitialized the next time an authentication attempt occurs. Should not be at this point
        // since CDI beans may not be available for injection yet.
        this.providersInitialized = false;
    }

    /**
     * Initializes the CDI beans and identity providers of this realm using the configuration parameters passed into the most recent call to
     * {@link #initialize(Map)}.
     */
    private void initializeProviders() {
        if (!providersInitialized) {
            if (log.isTraceEnabled()) {
                log.trace("Initializing beans and providers for " + DatawaveSecurityRealm.class.getName());
            }
            injectBeans();

            this.identityProviders = Set.copyOf(createProviders());
            if (log.isTraceEnabled()) {
                log.trace("Identity Providers initialized for " + DatawaveSecurityRealm.class.getName() + ": "
                                + this.identityProviders.stream().map(Object::getClass).collect(Collectors.toSet()));
            }
            providersInitialized = true;
        }
    }

    /**
     * Attempt to manually inject the CDI beans for this realm. If any required CDI beans are still null afterward, an {@link IllegalStateException} will be
     * thrown.
     */
    private void injectBeans() {
        log.trace("Injecting beans");
        if (userService == null || sslContextInfo == null) {
            BeanProvider.injectFields(this);
        }
        if (userService == null) {
            throw new IllegalStateException("Failed to inject " + DatawaveUserService.class.getName());
        }
        if (sslContextInfo == null) {
            throw new IllegalStateException("Failed to inject " + SSLContextInfo.class.getName());
        }
    }

    /**
     * Initialize the identity providers. These providers are in charge of authenticating a user and providing the required information needed to create a
     * {@link DatawavePrincipal} that is returned by a call to {@link RealmIdentity#getRealmIdentityPrincipal()} on the {@link RealmIdentity} returned by
     * {@link #getRealmIdentity(Evidence)}.
     */
    private Set<EvidenceIdentityProvider> createProviders() {
        log.trace("Creating providers");
        Set<EvidenceIdentityProvider> providers = new HashSet<>();

        // If JWT authentication is enabled, create a JWT identity provider.
        if (config.isJwtEnabled()) {
            log.trace("Creating JWT identity provider");
            providers.add(createJWTIdentityProvider());
        }

        // If trusted header authentication is enabled, create and add a trusted header identity provider.
        if (config.isTrustedHeadersEnabled()) {
            log.trace("Creating Trusted headers identity provider");
            providers.add(new TrustedHeaderEvidenceIdentityProvider(userService));
        }

        // Always add an identity provider for X509 certs. SSL authentication is always enabled.
        providers.add(createProxiedX509IdentityProvider());
        return providers;
    }

    /**
     * Create and return a new {@link JWTEvidenceIdentityProvider}.
     *
     * @return the identity provider
     */
    private JWTEvidenceIdentityProvider createJWTIdentityProvider() {
        try {
            // @formatter:off
            ObjectMapper mapper = JsonMapper.builder()
                            .enable(MapperFeature.USE_WRAPPER_NAME_AS_PROPERTY_NAME)
                            .build()
                            .registerModules(new GuavaModule())
                            .registerModules(new JaxbAnnotationModule());
            // @formatter:on
            String alias = sslContextInfo.getKeyStore().aliases().nextElement();
            X509KeyManager keyManager = (X509KeyManager) sslContextInfo.getKeyManagers()[0];
            X509Certificate[] certs = keyManager.getCertificateChain(alias);
            Key signingKey = keyManager.getPrivateKey(alias);

            JWTTokenHandler handler = new JWTTokenHandler(certs[0], signingKey, 24, TimeUnit.HOURS, JWTTokenHandler.TtlMode.RELATIVE_TO_CURRENT_TIME, mapper);
            return new JWTEvidenceIdentityProvider(handler);
        } catch (KeyStoreException e) {
            throw new RuntimeException("Failed to initialize JWTTokenHandler", e);
        }
    }

    /**
     * Create and return a new {@link ProxiedX509CertificateEvidenceIdentityProvider}.
     *
     * @return the identity provider
     */
    private ProxiedX509CertificateEvidenceIdentityProvider createProxiedX509IdentityProvider() {
        X509CertificateVerifier certVerifier = null;
        if (config.getCertVerifierClass() != null) {
            try {
                ClassLoader loader = Thread.currentThread().getContextClassLoader();
                Class<?> verifierClass = loader.loadClass(config.getCertVerifierClass());
                certVerifier = (X509CertificateVerifier) verifierClass.getDeclaredConstructor().newInstance();
                // Additional configuration required.
                if (certVerifier instanceof DatawaveCertVerifier) {
                    ((DatawaveCertVerifier) certVerifier).setLogger(log);
                    ((DatawaveCertVerifier) certVerifier).setOcspLevel(config.getOscpLevel());
                }
            } catch (Throwable e) {
                if (log.isTraceEnabled()) {
                    log.trace("Failed to create X509CertificateVerifier", e);
                }
                throw new IllegalArgumentException(e);
            }
        }
        return new ProxiedX509CertificateEvidenceIdentityProvider(userService, sslContextInfo, certVerifier);
    }

    @Override
    public void registerIdentityChangeListener(Consumer<Principal> listener) {
        // Todo - implement this so that the user service can notify this realm about changes to the underlying storage.
    }

    /**
     * Always returns {@link SupportLevel#UNSUPPORTED}.
     *
     * @return {@link SupportLevel#UNSUPPORTED}
     */
    @Override
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) {
        Preconditions.checkNotNull(credentialType, "Parameter credentialType cannot be null");
        return SupportLevel.UNSUPPORTED;
    }

    /**
     * Return a {@link SupportLevel} indicating if the given evidence type is one that any of the identity providers configured for this realm can provide an
     * identity for.
     *
     * @return {@link SupportLevel#SUPPORTED} if this realm has a configured identity provider that can handle the given evidence type, or
     *         {@link SupportLevel#UNSUPPORTED} otherwise
     */
    @Override
    public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) {
        Preconditions.checkNotNull(evidenceType, "Parameter evidenceType may not be null");
        // Ensure that identity providers have been initialized since the last call to initialize().
        initializeProviders();
        // @formatter:off
        return this.identityProviders.stream().anyMatch(provider -> provider.canProvideIdentityFrom(evidenceType)) ?
                        SupportLevel.SUPPORTED :
                        SupportLevel.UNSUPPORTED;
        // @formatter:on
    }

    @Override
    public RealmIdentity getRealmIdentity(Evidence evidence) {
        // Ensure that identity providers have been initialized since the last call to initialize().
        initializeProviders();
        return new DatawaveRealmIdentity(this, evidence);
    }

    /**
     * A {@link RealmIdentity} implementation that represents a specific authentication attempt against this security realm.
     */
    private static class DatawaveRealmIdentity implements RealmIdentity {

        private final DatawaveSecurityRealm datawaveSecurityRealm;

        /**
         * The underlying evidence representing the user to be authenticated.
         */
        private final Evidence evidence;

        /**
         * The identity found that is associated with the evidence.
         */
        private EvidenceIdentity identity;

        /**
         * Whether an attempt has been made to load the identity associated with the evidence.
         */
        private boolean loaded = false;

        public DatawaveRealmIdentity(DatawaveSecurityRealm datawaveSecurityRealm, Evidence evidence) {
            this.datawaveSecurityRealm = datawaveSecurityRealm;
            this.evidence = evidence;
        }

        @Override
        public Principal getRealmIdentityPrincipal() {
            try {
                if (exists()) {
                    return new DatawavePrincipal(identity.getUsers());
                }
            } catch (RealmUnavailableException e) {
                return null;
            }
            return null;
        }

        @Override
        public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName,
                        AlgorithmParameterSpec parameterSpec) {
            return SupportLevel.UNSUPPORTED;
        }

        @Override
        public <C extends Credential> C getCredential(Class<C> credentialType) {
            return null;
        }

        @Override
        public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) {
            Preconditions.checkNotNull(evidenceType, "Parameter evidenceType may not be null");
            return datawaveSecurityRealm.getEvidenceVerifySupport(evidenceType, algorithmName);
        }

        @Override
        public boolean verifyEvidence(Evidence evidence) throws RealmUnavailableException {
            Preconditions.checkNotNull(evidence, "Parameter evidence may not be null");
            getIdentity();
            return exists();
        }

        @Override
        public AuthorizationIdentity getAuthorizationIdentity() throws RealmUnavailableException {
            return exists() ? AuthorizationIdentity.basicIdentity(identity.getAttributes()) : AuthorizationIdentity.EMPTY;
        }

        @Override
        public boolean exists() throws RealmUnavailableException {
            return getIdentity() != null;
        }

        private EvidenceIdentity getIdentity() {
            if (!loaded && this.identity == null && evidence != null) {
                // @formatter:off
                EvidenceIdentityProvider identityProvider = datawaveSecurityRealm.identityProviders.stream()
                                .filter(provider -> provider.canProvideIdentityFrom(evidence.getClass()))
                                .findFirst()
                                .orElse(null);
                // @formatter:on
                if (identityProvider != null) {
                    this.identity = identityProvider.getIdentity(evidence);
                    if (this.identity != null) {
                        DatawavePrincipal principal = new DatawavePrincipal(identity.getUsers());
                        if (isAnyUserDeniedAccess(principal)) {
                            if (log.isTraceEnabled()) {
                                log.trace("User " + principal.getPrimaryUser().getDn() + " has access-denied role "
                                                + datawaveSecurityRealm.config.getAccessDeniedRole());
                            }
                            this.identity = null;
                        } else if (hasInvalidTerminalServer(principal)) {
                            if (log.isTraceEnabled()) {
                                log.trace("User " + principal.getPrimaryUser().getDn() + " has proxied server without required terminal server role");
                            }
                            this.identity = null;
                        } else {
                            Attributes attributes = getAttributes(principal);
                            this.identity = new EvidenceIdentity(this.identity.getUsers(), attributes);
                        }

                    }

                }
                this.loaded = true;
            }
            return this.identity;
        }

        /**
         * Return whether any user in the chain for the given principal has the access denied role.
         *
         * @param principal
         *            the principal to validate
         * @return true if any user in the chain is denied access, or false otherwise
         */
        private boolean isAnyUserDeniedAccess(DatawavePrincipal principal) {
            if (datawaveSecurityRealm.config.getAccessDeniedRole() != null) {
                String accessDeniedRole = datawaveSecurityRealm.config.getAccessDeniedRole();
                return principal.getProxiedUsers().stream().anyMatch(user -> user.getRoles().contains(accessDeniedRole));
            }
            return false;
        }

        /**
         * Return whether the given principal has an invalid terminal server as the last user in the chain. The principal is considered to have an invalid
         * terminal server if the last user in its user chain is a server, and it does not have any of the required terminal server roles.
         *
         * @param principal
         *            the principal to validate
         * @return true if the principal has an invalid terminal server, or false otherwise
         */
        private boolean hasInvalidTerminalServer(DatawavePrincipal principal) {
            // Stream through the user chain to get the last user.
            DatawaveUser lastUser = principal.getProxiedUsers().stream().reduce((prev, next) -> next).orElse(null);
            Set<String> terminalServerRoles = datawaveSecurityRealm.config.getTerminalServerRoles();
            return lastUser == null || (lastUser.getUserType() == DatawaveUser.UserType.SERVER
                            && lastUser.getRoles().stream().noneMatch(terminalServerRoles::contains));
        }

        /**
         * Return a {@link Attributes} that contains the roles of the primary user and of the proxied users. This will be used by the
         * {@link RequiredRoleDecoder} to establish what roles a user has.
         *
         * @param principal
         *            the principal to extract attributes from
         * @return the attributes
         */
        private Attributes getAttributes(DatawavePrincipal principal) {
            MapAttributes mapAttributes = new MapAttributes();
            DatawaveUser primaryUser = principal.getPrimaryUser();
            if (primaryUser != null) {
                primaryUser.getRoles().forEach(role -> mapAttributes.addLast(RequiredRoleDecoder.PRIMARY_USER_ROLES, role));
            }
            // @formatter:off
            principal.getProxiedUsers().stream()
                            .map(DatawaveUser::getRoles)
                            .flatMap(Collection::stream)
                            .forEach(role -> mapAttributes.addLast(RequiredRoleDecoder.PROXIED_USER_ROLES, role));
            // @formatter:on
            return mapAttributes.asReadOnly();
        }

    }

}
