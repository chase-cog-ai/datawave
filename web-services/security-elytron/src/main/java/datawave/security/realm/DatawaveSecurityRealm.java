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

public class DatawaveSecurityRealm implements CacheableSecurityRealm {
    
    private final Logger log = Logger.getLogger(DatawaveSecurityRealm.class);
    
    private static final String OPTION_JWT_ENABLED = "jwtEnabled";
    private static final String OPTION_TRUSTED_HEADERS_ENABLED = "trustedHeadersEnabled";
    private static final String OPTION_CERT_VERIFIER_CLASS = "certVerifierClass";
    private static final String OPTION_OSCP_LEVEL = "oscpLevel";
    
    @Inject
    private DatawaveUserService userService;
    
    @Inject
    private SSLContextInfo sslContextInfo;
    
    private Set<DatawaveIdentityProvider> identityProviders = null;
    
    private Map<String, String> config = Map.of();
    private boolean realmInitialized = false;
    
    public void initialize(Map<String,String> config) {
        if(log.isTraceEnabled()) {
            log.trace("Initializing " + DatawaveSecurityRealm.class.getName() + " with config=" + config);
        }
        this.config = Map.copyOf(config);
        this.realmInitialized = false;
    }
    
    private void initRealm() {
        if (!realmInitialized) {
            injectBeans();
            initProviders();
            realmInitialized = true;
        }
    }
    
    private void injectBeans() {
        log.trace("Injecting beans");
        if(userService == null || sslContextInfo == null) {
            BeanProvider.injectFields(this);
        }
        if(userService == null) {
            throw new IllegalStateException("Failed to inject DatawaveUserService");
        }
        if(sslContextInfo == null) {
            throw new IllegalStateException("Failed to inject SSLSessionInfo");
        }
    }
    
    private void initProviders() {
        Set<DatawaveIdentityProvider> providers = new HashSet<>();
        
        // If JWT authentication is enabled, create and add a JWT identity provider.
        boolean jwtEnabled = Boolean.parseBoolean(config.get(OPTION_JWT_ENABLED));
        if(log.isTraceEnabled()) {
            log.trace("JWT authentication enabled: " + jwtEnabled);
        }
        if (jwtEnabled) {
            log.trace("Creating JWT identity provider");
            providers.add(new JWTIdentityProvider());
        }
        
        // If trusted header authentication is enabled, create and add a trusted header identity provider.
        boolean trustedHeadersEnabled = Boolean.parseBoolean(config.get(OPTION_TRUSTED_HEADERS_ENABLED));
        if(log.isTraceEnabled()) {
            log.trace("Trusted headers authentication enabled: " + trustedHeadersEnabled);
        }
        if (trustedHeadersEnabled) {
            log.trace("Creating Trusted headers identity provider");
            providers.add(new TrustedHeaderIdentityProvider());
        }
        
        // Always add an identity provider for X509 certs.
        String certVerifierClass = config.get(OPTION_CERT_VERIFIER_CLASS);
        String oscpLevel = config.get(OPTION_OSCP_LEVEL);
        try {
            if(log.isTraceEnabled()) {
                log.trace("Creating proxied X509Certificate identity provider");
            }
            providers.add(new ProxiedX509IdentityProvider(certVerifierClass, oscpLevel));
        } catch (IllegalArgumentException e) {
            throw new RuntimeException(e);
        }
        
        this.identityProviders = Set.copyOf(providers);
    }
    
    @Override
    public void registerIdentityChangeListener(Consumer<Principal> listener) {
        // Todo - implement this so that the user service can notify this realm about changes to the underlying storage.
    }
    
    @Override
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) {
        Preconditions.checkNotNull(credentialType, "Parameter credentialType may not be null");
        return SupportLevel.POSSIBLY_SUPPORTED;
    }
    
    @Override
    public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) {
        Preconditions.checkNotNull(evidenceType, "Parameter evidenceType may not be null");
        initRealm();
        // @formatter:off
        return this.identityProviders.stream().anyMatch(provider -> provider.canProvideIdentityFrom(evidenceType)) ?
                        SupportLevel.SUPPORTED :
                        SupportLevel.UNSUPPORTED;
        // @formatter:on
    }
    
    @Override
    public RealmIdentity getRealmIdentity(Evidence evidence) {
        initRealm();
        return new DatawaveRealmIdentity(evidence);
    }
    
    private class DatawaveRealmIdentity implements RealmIdentity {
        
        private final Evidence evidence;
        private DatawaveIdentity identity;
        private boolean loaded = false;
    
        public DatawaveRealmIdentity(Evidence evidence) {
            if(evidence instanceof ProxiedX509CertificateEvidence || evidence instanceof TrustedHeaderEvidence || evidence instanceof JWTEvidence) {
                this.evidence = evidence;
            } else {
                this.evidence = null;
            }
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
        
        private DatawaveIdentity getIdentity() {
            if(!loaded && this.identity == null) {
                if(evidence != null) {
                    // @formatter:off
                    DatawaveIdentityProvider identityProvider = identityProviders.stream()
                                    .filter(provider -> provider.canProvideIdentityFrom(evidence.getClass()))
                                    .findFirst()
                                    .orElse(null);
                    // @formatter:on
                    if(identityProvider != null) {
                        this.identity = identityProvider.getIdentity(evidence);
                    }
                }
                this.loaded = true;
            }
            return this.identity;
        }
    }
    
    private static class DatawaveIdentity {
        private final Collection<DatawaveUser> users;
        private final Attributes attributes;
        
        public DatawaveIdentity(Collection<DatawaveUser> users) {
            this.users = Collections.unmodifiableCollection(users);
            this.attributes = buildAttributes(users);
        }
        
        protected Attributes buildAttributes(Collection<DatawaveUser> users) {
            if(users != null && users.isEmpty()) {
                DatawavePrincipal principal = new DatawavePrincipal(users);
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
            } else {
                return Attributes.EMPTY;
            }
        }
    }
    
    private interface DatawaveIdentityProvider {
        
        default boolean canProvideIdentityFrom(Class<? extends Evidence> evidenceType) {
            return evidenceType.equals(getEvidenceSupportType());
        }
        
        Class<? extends Evidence> getEvidenceSupportType();
        
        DatawaveIdentity getIdentity(Evidence evidence);
    }
    
    private class JWTIdentityProvider implements DatawaveIdentityProvider {
        
        private final JWTTokenHandler jwtTokenHandler;
        
        private JWTIdentityProvider() {
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
                
                this.jwtTokenHandler = new JWTTokenHandler(certs[0], signingKey, 24, TimeUnit.HOURS, JWTTokenHandler.TtlMode.RELATIVE_TO_CURRENT_TIME, mapper);
            } catch (KeyStoreException e) {
                throw new RuntimeException("Failed to initialize JWTTokenHandler", e);
            }
        }
        
        @Override
        public Class<? extends Evidence> getEvidenceSupportType() {
            return JWTEvidence.class;
        }
        
        @Override
        public DatawaveIdentity getIdentity(Evidence evidence) {
            Preconditions.checkNotNull(evidence, "Evidence may not be null");
            Preconditions.checkArgument(evidence.getClass().equals(getEvidenceSupportType()), "Evidence must be an instance of " + getEvidenceSupportType().getName());
            
            JWTEvidence jwtEvidence = (JWTEvidence) evidence;
            Collection<DatawaveUser> users = jwtTokenHandler.createUsersFromToken(jwtEvidence.getToken());
            return new DatawaveIdentity(users);
        }
    }
    
    private class TrustedHeaderIdentityProvider implements DatawaveIdentityProvider {
        
        @Override
        public Class<? extends Evidence> getEvidenceSupportType() {
            return TrustedHeaderEvidence.class;
        }
        
        @Override
        public DatawaveIdentity getIdentity(Evidence evidence) {
            Preconditions.checkNotNull(evidence, "Evidence may not be null");
            Preconditions.checkArgument(evidence.getClass().equals(getEvidenceSupportType()), "Evidence must be an instance of " + getEvidenceSupportType().getName());
            
            TrustedHeaderEvidence trustedHeaderEvidence = (TrustedHeaderEvidence) evidence;
            
            try {
                Collection<DatawaveUser> users = userService.lookup(trustedHeaderEvidence.getEntities());
                return new DatawaveIdentity(users);
            } catch (AuthorizationException e) {
                throw new RuntimeException(e);
            }
        }
    }
    
    private class ProxiedX509IdentityProvider implements DatawaveIdentityProvider {
        
        private final X509CertificateVerifier certVerifier;
        
        private ProxiedX509IdentityProvider(String certVerifierClass, String oscpLevel) throws IllegalArgumentException {
            if (certVerifierClass != null) {
                try {
                    ClassLoader loader = Thread.currentThread().getContextClassLoader();
                    Class<?> verifierClass = loader.loadClass(certVerifierClass);
                    certVerifier = (X509CertificateVerifier) verifierClass.getDeclaredConstructor().newInstance();
                    if (certVerifier instanceof DatawaveCertVerifier) {
                        ((DatawaveCertVerifier) certVerifier).setLogger(log);
                        ((DatawaveCertVerifier) certVerifier).setOcspLevel(oscpLevel);
                    }
                } catch (Throwable e) {
                    if (log.isTraceEnabled()) {
                        log.trace("Failed to create X509CertificateVerifier", e);
                    }
                    throw new IllegalArgumentException(e);
                }
            } else {
                certVerifier = null;
            }
        }
        
        @Override
        public Class<? extends Evidence> getEvidenceSupportType() {
            return ProxiedX509CertificateEvidence.class;
        }
        
        @Override
        public DatawaveIdentity getIdentity(Evidence evidence) {
            Preconditions.checkNotNull(evidence, "Evidence may not be null");
            Preconditions.checkArgument(evidence.getClass().equals(getEvidenceSupportType()), "Evidence must be an instance of " + getEvidenceSupportType().getName());
            
            ProxiedX509CertificateEvidence certificateEvidence = (ProxiedX509CertificateEvidence) evidence;
            if(isValidCertificate(certificateEvidence.getCertificate())) {
                try {
                    Collection<DatawaveUser> users = userService.lookup(certificateEvidence.getEntities());
                    return new DatawaveIdentity(users);
                } catch (AuthorizationException e) {
                    throw new RuntimeException(e);
                }
            }
            
            return null;
        }
        
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
