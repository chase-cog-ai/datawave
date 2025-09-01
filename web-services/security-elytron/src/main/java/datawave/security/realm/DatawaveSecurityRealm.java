package datawave.security.realm;

import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.guava.GuavaModule;
import com.fasterxml.jackson.module.jaxb.JaxbAnnotationModule;
import com.google.common.base.Preconditions;
import datawave.configuration.spring.BeanProvider;
import datawave.security.SSLContextInfo;
import datawave.security.authorization.AuthorizationException;
import datawave.security.authorization.DatawavePrincipal;
import datawave.security.authorization.DatawaveUser;
import datawave.security.authorization.DatawaveUserService;
import datawave.security.authorization.JWTTokenHandler;
import datawave.security.cert.DatawaveCertVerifier;
import datawave.security.cert.X509CertificateVerifier;
import datawave.security.evidence.JWTEvidence;
import datawave.security.evidence.ProxiedX509CertificateEvidence;
import datawave.security.evidence.TrustedHeaderEvidence;
import datawave.util.StringUtils;
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

import javax.inject.Inject;
import javax.net.ssl.X509KeyManager;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.stream.Collectors;

public class DatawaveSecurityRealm implements CacheableSecurityRealm {
    
    private final Logger log = Logger.getLogger(DatawaveSecurityRealm.class);
    
    /**
     * Whether JWT authentication is enabled.
     */
    static final String OPTION_JWT_ENABLED = "jwtEnabled";
    
    /**
     * Whether trusted header authentication is enabled.
     */
    static final String OPTION_TRUSTED_HEADERS_ENABLED = "trustedHeadersEnabled";
    
    /**
     * The fully qualified name of the certificate verifier class to use to verify the user cert during SSL authentication. Must be a class that implements 4
     * {@link X509CertificateVerifier}.
     */
    static final String OPTION_CERT_VERIFIER = "certVerifier";
    
    /**
     * The OSCP level to set in the certificate verifier instance if it is an instance of {@link DatawaveCertVerifier}.
     */
    static final String OPTION_OSCP_LEVEL = "oscpLevel";
    
    /**
     * The role that, if a user has it, should result in them being denied access.
     */
    static final String OPTION_ACCESS_DENIED_ROLE = "accessDeniedRole";
    
    /**
     * The roles that the terminal server in a user's proxied cert
     */
    static final String OPTION_TERMINAL_SERVER_ROLES = "terminalServerRoles";
    
    private static final Set<String> defaultTerminalServerRoles = Set.of(DatawaveRoles.ROLE_AUTHORIZED_SERVER, DatawaveRoles.ROLE_AUTHORIZED_QUERY_SERVER);
    
    /**
     * The user service.
     */
    @Inject
    private DatawaveUserService userService;
    
    /**
     * The SSL context info.
     */
    @Inject
    private SSLContextInfo sslContextInfo;
    
    /**
     * The configuration properties. This is updated every time {@link #initialize(Map)} is called.
     */
    private DatawaveSecurityRealmConfig config = null;
    
    /**
     * The configured identity providers. These are established the first time {@link DatawaveSecurityRealm#initializeProviders()} is called.
     */
    private Set<IdentityProvider> identityProviders = null;
    
    /**
     * Whether {@link DatawaveSecurityRealm#initializeProviders()} has ever been called.
     */
    private boolean providersInitialized = false;
    
    /**
     * This method is invoked by the Wildfly Elytron subsystem during the realm's lifecycle to provide configuration parameters. These parameters are typically
     * defined in the Wildfly configuration files, such as jboss .cli files or in the standalone.xml. There is no guarantee that beans will be available for
     * injection at the time that this method is invoked, so any manual injection of beans should be delayed until the first authentication attempt.
     * <p>
     * NOTE: Any configuration parameters passed into here will be parsed and stored, but any configuration requiring the presence of CDI beans will not take
     * effect until the next time either @link #getRealmIdentity(Evidence)} or {@link #getEvidenceVerifySupport(Class, String)}is called.
     * <p>
     * Supported configuration parameters:
     * <ul>
     * <li>{@value OPTION_JWT_ENABLED}: A boolean that denotes whether JWT authentication is enabled for this realm. Defaults to false.</li>
     * <li>{@value OPTION_TRUSTED_HEADERS_ENABLED}: A boolean that denotes whether trusted header authentication is enabled for this realm. Defaults to false.
     * </li>
     * <li>{@value OPTION_CERT_VERIFIER}: The fully qualified class name of the {@link X509CertificateVerifier} implementation to verify user certificates
     * with. Defaults to null.</li>
     * <li>{@value OPTION_OSCP_LEVEL}: The oscp level to set in the {@link X509CertificateVerifier} if the class specified is assignable from
     * {@link DatawaveCertVerifier}. Defaults to null.</li>
     * <li>{@value OPTION_ACCESS_DENIED_ROLE}: The catch-all access denied role. If any user in a chain of users has this role, they will all be denied access.
     * Defaults to null.</li>
     * <li>{@value OPTION_TERMINAL_SERVER_ROLES}: A colon-delimited list of roles that the last proxied user in the certificate chain must, if the user is a
     * server, be assigned at least one of. Defaults to the roles {@value DatawaveRoles#ROLE_AUTHORIZED_SERVER} and
     * {@value DatawaveRoles#ROLE_AUTHORIZED_QUERY_SERVER}</li>
     * </ul>
     * @param config the configuration parameters
     */
    public void initialize(Map<String,String> config) {
        if(log.isTraceEnabled()) {
            log.trace("Initializing " + DatawaveSecurityRealm.class.getName() + " with config=" + config);
        }
        // Parse the configuration properties.
        this.config = new DatawaveSecurityRealmConfig(config);
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
            if(log.isTraceEnabled()) {
                log.trace("Initializing beans and providers for " + DatawaveSecurityRealm.class.getName());
            }
            injectBeans();
            
            this.identityProviders = Set.copyOf(createProviders());
            if(log.isTraceEnabled()) {
                log.trace("Identity Providers initialized for " + DatawaveSecurityRealm.class.getName() + ": " +
                                this.identityProviders.stream().map(Object::getClass).collect(Collectors.toSet()));
            }
            providersInitialized = true;
        }
    }
    
    /**
     * Attempt to manually inject the CDI beans for this realm. If any required CDI beans are still null afterward, a {@link IllegalStateException} will be
     * thrown.
     */
    private void injectBeans() {
        log.trace("Injecting beans");
        if(userService == null || sslContextInfo == null) {
            BeanProvider.injectFields(this);
        }
        if(userService == null) {
            throw new IllegalStateException("Failed to inject " + DatawaveUserService.class.getName());
        }
        if(sslContextInfo == null) {
            throw new IllegalStateException("Failed to inject " + SSLContextInfo.class.getName());
        }
    }
    
    /**
     * Initialize the identity providers. These providers are in charge of authenticating a user and providing the required information needed to create a
     * {@link DatawavePrincipal} that is returned by a call to {@link RealmIdentity#getRealmIdentityPrincipal()} on the {@link RealmIdentity} returned by
     * {@link #getRealmIdentity(Evidence)}.
     */
    private Set<IdentityProvider> createProviders() {
        log.trace("Creating providers");
        Set<IdentityProvider> providers = new HashSet<>();
        
        // If JWT authentication is enabled, create a JWT identity provider.
        if (config.jwtEnabled) {
            log.trace("Creating JWT identity provider");
            providers.add(createJWTIdentityProvider());
        }
        
        // If trusted header authentication is enabled, create and add a trusted header identity provider.
        if (config.trustedHeadersEnabled) {
            log.trace("Creating Trusted headers identity provider");
            providers.add(new TrustedHeaderIdentityProvider(config.accessDeniedRole, config.terminalServerRoles));
        }
        
        // Always add an identity provider for X509 certs. SSL authentication is always enabled.
        providers.add(createProxiedX509IdentityProvider());
        return providers;
    }
    
    /**
     * Create and return a new {@link JWTIdentityProvider}.
     * @return the identity provider
     */
    private JWTIdentityProvider createJWTIdentityProvider() {
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
            return new JWTIdentityProvider(config.accessDeniedRole, config.terminalServerRoles, handler);
        } catch (KeyStoreException e) {
            throw new RuntimeException("Failed to initialize JWTTokenHandler", e);
        }
    }
    
    /**
     * Create and return a new {@link ProxiedX509IdentityProvider}.
     * @return the identity provider
     */
    private ProxiedX509IdentityProvider createProxiedX509IdentityProvider() {
        X509CertificateVerifier certVerifier = null;
        if (config.certVerifierClass != null) {
            try {
                ClassLoader loader = Thread.currentThread().getContextClassLoader();
                Class<?> verifierClass = loader.loadClass(config.certVerifierClass);
                certVerifier = (X509CertificateVerifier) verifierClass.getDeclaredConstructor().newInstance();
                // Additional configuration required.
                if (certVerifier instanceof DatawaveCertVerifier) {
                    ((DatawaveCertVerifier) certVerifier).setLogger(log);
                    ((DatawaveCertVerifier) certVerifier).setOcspLevel(config.oscpLevel);
                }
            } catch (Throwable e) {
                if (log.isTraceEnabled()) {
                    log.trace("Failed to create X509CertificateVerifier", e);
                }
                throw new IllegalArgumentException(e);
            }
        }
        return new ProxiedX509IdentityProvider(config.accessDeniedRole, config.terminalServerRoles, certVerifier);
    }
    
    @Override
    public void registerIdentityChangeListener(Consumer<Principal> listener) {
        // Todo - implement this so that the user service can notify this realm about changes to the underlying storage.
    }
    
    /**
     * Always returns {@link SupportLevel#UNSUPPORTED}.
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
     * @return {@link SupportLevel#SUPPORTED} if this realm has a configured identity provider that can handle the given evidence type, or
     * {@link SupportLevel#UNSUPPORTED} otherwise
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
        return new DatawaveRealmIdentity(evidence);
    }
    
    private static class DatawaveSecurityRealmConfig {
        
        private final boolean jwtEnabled;
        private final boolean trustedHeadersEnabled;
        private final String certVerifierClass;
        private final String oscpLevel;
        private final String accessDeniedRole;
        private final Set<String> terminalServerRoles;
        
        private DatawaveSecurityRealmConfig(Map<String, String> config) {
            this.jwtEnabled = Boolean.parseBoolean(config.get(OPTION_JWT_ENABLED));
            this.trustedHeadersEnabled = Boolean.parseBoolean(config.get(OPTION_TRUSTED_HEADERS_ENABLED));
            this.certVerifierClass = config.get(OPTION_CERT_VERIFIER);
            this.oscpLevel = config.get(OPTION_OSCP_LEVEL);
            
            String accessDeniedRoleOption = config.get(OPTION_ACCESS_DENIED_ROLE);
            if(accessDeniedRoleOption != null) {
                accessDeniedRoleOption = accessDeniedRoleOption.trim();
                this.accessDeniedRole = accessDeniedRoleOption.isEmpty() ? null : accessDeniedRoleOption;
            } else {
                this.accessDeniedRole = null;
            }
            
            String terminalServerRolesOption = config.get(OPTION_TERMINAL_SERVER_ROLES);
            if(terminalServerRolesOption != null) {
                terminalServerRoles = Set.of(StringUtils.split(terminalServerRolesOption, ':'));
            } else {
                this.terminalServerRoles = defaultTerminalServerRoles;
            }
        }
    }
    
    /**
     * A {@link RealmIdentity} implementation that represents a specific authentication attempt against this security realm.
     */
    private class DatawaveRealmIdentity implements RealmIdentity {
        
        /**
         * The underlying evidence representing the user to be authenticated.
         */
        private final Evidence evidence;
        
        /**
         * The identity found that is associated with the evidence.
         */
        private Identity identity;
        
        /**
         * Whether an attempt has been made to load the identity associated with the evidence.
         */
        private boolean loaded = false;
        
        public DatawaveRealmIdentity(Evidence evidence) {
            this.evidence = evidence;
        }
        
        @Override
        public Principal getRealmIdentityPrincipal() {
            try {
                if (exists()) {
                    return new DatawavePrincipal(identity.users);
                }
            } catch (RealmUnavailableException e) {
                return null;
            }
            return null;
        }
        
        @Override
        public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) {
            return SupportLevel.UNSUPPORTED;
        }
        
        @Override
        public <C extends Credential> C getCredential(Class<C> credentialType) {
            return null;
        }
        
        @Override
        public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) {
            Preconditions.checkNotNull(evidenceType, "Parameter evidenceType may not be null");
            return DatawaveSecurityRealm.this.getEvidenceVerifySupport(evidenceType, algorithmName);
        }
        
        @Override
        public boolean verifyEvidence(Evidence evidence) throws RealmUnavailableException {
            Preconditions.checkNotNull(evidence, "Parameter evidence may not be null");
            getIdentity();
            return exists();
        }
        
        @Override
        public AuthorizationIdentity getAuthorizationIdentity() throws RealmUnavailableException {
            return exists() ? AuthorizationIdentity.basicIdentity(identity.attributes) : AuthorizationIdentity.EMPTY;
        }
        
        @Override
        public boolean exists() throws RealmUnavailableException {
            return getIdentity() != null;
        }
        
        private Identity getIdentity() {
            if(!loaded && this.identity == null && evidence != null) {
                // @formatter:off
                IdentityProvider identityProvider = identityProviders.stream()
                                .filter(provider -> provider.canProvideIdentityFrom(evidence.getClass()))
                                .findFirst()
                                .orElse(null);
                // @formatter:on
                if(identityProvider != null) {
                    this.identity = identityProvider.getIdentity(evidence);
                }
                this.loaded = true;
            }
            return this.identity;
        }
    }
    
    /**
     * Represents information found in the datawave system for a particular user after an authentication attempt.
     */
    private static class Identity {
        
        private final Collection<DatawaveUser> users;
        private final Attributes attributes;
        
        public Identity(Collection<DatawaveUser> users, Attributes attributes) {
            this.users = Collections.unmodifiableCollection(users);
            this.attributes = attributes;
        }
    }
    
    /**
     * Represents a method of identifying a user identity associated with a particular type of evidence.
     */
    private interface IdentityProvider {
        
        /**
         * Return whether this provider supports attempting to provide an identity for the given evidence type.
         * @param evidenceType the evidence type
         * @return true if this provider supports providing an identity for the given evidence type, or false otherwise
         */
        boolean canProvideIdentityFrom(Class<? extends Evidence> evidenceType);
        
        /**
         * Returns the user identity information associated with the given evidence, or null if no identity could be found.
         * @param evidence the evidence
         * @return the identity, possibly null
         */
        Identity getIdentity(Evidence evidence);
    }
    
    /**
     * Base implementation of {@link IdentityProvider} that provides functionality for validating the roles of a collection of {@link DatawaveUser} that would
     * make up a {@link DatawavePrincipal}.
     */
    private static abstract class AbstractIdentityProvider implements IdentityProvider {
    
        protected final String accessDeniedRole;
        protected final Set<String> terminalServerRoles;
        
        public AbstractIdentityProvider(String accessDeniedRole, Set<String> terminalServerRoles) {
            Preconditions.checkNotNull(accessDeniedRole, "Parameter accessDeniedRole may not be null");
            Preconditions.checkNotNull(terminalServerRoles, "Parameter terminalServerRoles may not be null");
            this.accessDeniedRole = accessDeniedRole;
            this.terminalServerRoles = Set.copyOf(terminalServerRoles);
        }
        
        /**
         * Attempt to validate and create an identity from the given collection of users.
         * @param users the users
         * @return the created identity, or null if no valid identity could be created
         */
        protected Identity validateAndCreateIdentity(Collection<DatawaveUser> users) {
            if(users != null && users.isEmpty()) {
                DatawavePrincipal principal = new DatawavePrincipal(users);
                // If no users are denied access, and there is no invalid terminal server, create and return an identity.
                if (!isAnyUserDeniedAccess(principal) && !hasInvalidTerminalServer(principal)) {
                    Attributes attributes = getAttributes(principal);
                    return new Identity(users, attributes);
                }
            }
            // Otherwise, return null to indicate a non-valid identity.
            return null;
        }
        
        /**
         * Return whether any user in the chain for the given principal has the access denied role.
         * @param principal the principal to validate
         * @return true if any user in the chain is denied access, or false otherwise
         */
        protected boolean isAnyUserDeniedAccess(DatawavePrincipal principal) {
            if (accessDeniedRole != null) {
                return principal.getProxiedUsers().stream().anyMatch(user -> user.getRoles().contains(accessDeniedRole));
            }
            return false;
        }
        
        /**
         * Return whether the given principal has an invalid terminal server as the last user in the chain. The principal is considered to have an invalid
         * terminal server if the last user in its user chain is a server, and it does not have any of the required terminal server roles.
         * @param principal the principal to validate
         * @return true if the principal has an invalid terminal server, or false otherwise
         */
        protected boolean hasInvalidTerminalServer(DatawavePrincipal principal) {
            // Stream through the user chain to get the last user.
            DatawaveUser lastUser = principal.getProxiedUsers().stream().reduce((prev, next) -> next).orElse(null);
            return lastUser == null || (lastUser.getUserType() == DatawaveUser.UserType.SERVER &&
                            lastUser.getRoles().stream().noneMatch(terminalServerRoles::contains));
        }
        
        /**
         * Return a {@link Attributes} that contains the roles of the primary user and of the proxied users. This will be used by the
         * {@link RequiredRoleDecoder} to establish what roles a user has.
         * @param principal the principal to extract attributes from
         * @return the attributes
         */
        protected Attributes getAttributes(DatawavePrincipal principal) {
            MapAttributes mapAttributes = new MapAttributes();
            DatawaveUser primaryUser = principal.getPrimaryUser();
            if(primaryUser != null) {
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
    
    /**
     * {@link IdentityProvider} implementation for JWT authentication.
     */
    private static class JWTIdentityProvider extends AbstractIdentityProvider {
        
        private final JWTTokenHandler jwtTokenHandler;
        
        private JWTIdentityProvider(String accessDeniedRole, Set<String> terminalServerRoles, JWTTokenHandler jwtTokenHandler) {
            super(accessDeniedRole, terminalServerRoles);
            Preconditions.checkNotNull(jwtTokenHandler, "Parameter jwtTokenHandler may not be null");
            this.jwtTokenHandler = jwtTokenHandler;
        }
        
        @Override
        public boolean canProvideIdentityFrom(Class<? extends Evidence> evidenceType) {
            return JWTEvidence.class.equals(evidenceType);
        }
        
        @Override
        public Identity getIdentity(Evidence evidence) {
            Preconditions.checkNotNull(evidence, "Evidence may not be null");
            Preconditions.checkArgument(canProvideIdentityFrom(evidence.getClass()), "Evidence type " + evidence.getClass() + " is not supported");
            
            JWTEvidence jwtEvidence = (JWTEvidence) evidence;
            Collection<DatawaveUser> users = jwtTokenHandler.createUsersFromToken(jwtEvidence.getToken());
            return validateAndCreateIdentity(users);
        }
    }
    
    /**
     * {@link IdentityProvider} implementation for trusted header authentication.
     */
    private class TrustedHeaderIdentityProvider extends AbstractIdentityProvider {
        
        public TrustedHeaderIdentityProvider(String accessDeniedRole, Set<String> terminalServerRoles) {
            super(accessDeniedRole, terminalServerRoles);
        }
        
        @Override
        public boolean canProvideIdentityFrom(Class<? extends Evidence> evidenceType) {
            return TrustedHeaderEvidence.class.equals(evidenceType);
        }
        
        @Override
        public Identity getIdentity(Evidence evidence) {
            Preconditions.checkNotNull(evidence, "Evidence may not be null");
            Preconditions.checkArgument(canProvideIdentityFrom(evidence.getClass()), "Evidence type " + evidence.getClass() + " is not supported");
            
            TrustedHeaderEvidence trustedHeaderEvidence = (TrustedHeaderEvidence) evidence;
            
            try {
                Collection<DatawaveUser> users = userService.lookup(trustedHeaderEvidence.getEntities());
                return validateAndCreateIdentity(users);
            } catch (AuthorizationException e) {
                throw new RuntimeException(e);
            }
        }
    }
    
    /**
     * {@link IdentityProvider} implementation for SSL cert authentication.
     */
    private class ProxiedX509IdentityProvider extends AbstractIdentityProvider {
        
        private final X509CertificateVerifier certVerifier;
        
        private ProxiedX509IdentityProvider(String accessDeniedRole, Set<String> terminalServerRoles, X509CertificateVerifier certVerifier) throws IllegalArgumentException {
            super(accessDeniedRole, terminalServerRoles);
            this.certVerifier = certVerifier;
        }
        
        @Override
        public boolean canProvideIdentityFrom(Class<? extends Evidence> evidenceType) {
            return ProxiedX509CertificateEvidence.class.equals(evidenceType);
        }
        
        @Override
        public Identity getIdentity(Evidence evidence) {
            Preconditions.checkNotNull(evidence, "Evidence may not be null");
            Preconditions.checkArgument(canProvideIdentityFrom(evidence.getClass()), "Evidence type " + evidence.getClass() + " is not supported");
            
            ProxiedX509CertificateEvidence certificateEvidence = (ProxiedX509CertificateEvidence) evidence;
            // Validate the provided certificate.
            if(isValidCertificate(certificateEvidence.getCertificate())) {
                try {
                    Collection<DatawaveUser> users = userService.lookup(certificateEvidence.getEntities());
                    return validateAndCreateIdentity(users);
                } catch (AuthorizationException e) {
                    throw new RuntimeException(e);
                }
            }
            
            return null;
        }
        
        /**
         * Return whether the given certificate is considered valid.
         * @param certificate the certificate to validate
         * @return true if the certificate is valid, or false otherwise
         */
        private boolean isValidCertificate(X509Certificate certificate) {
            KeyStore keyStore = sslContextInfo.getKeyStore();
            KeyStore trustStore = sslContextInfo.getTrustStore();
            if(trustStore != null) {
                trustStore = keyStore;
            }
            
            if (certVerifier != null) {
                String alias = certificate.getIssuerX500Principal().getName();
                if (certVerifier instanceof DatawaveCertVerifier && !((DatawaveCertVerifier) certVerifier).isIssuerSupported(alias, trustStore)) {
                    return false;
                }
                return certVerifier.verify(certificate, alias, keyStore, trustStore);
            } else {
                return true;
            }
        }
    }
}
