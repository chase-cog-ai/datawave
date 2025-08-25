package datawave.security.realm;

import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.guava.GuavaModule;
import com.fasterxml.jackson.module.jaxb.JaxbAnnotationModule;
import datawave.configuration.spring.BeanProvider;
import datawave.security.SSLContextInfo;
import datawave.security.authorization.DatawavePrincipal;
import datawave.security.authorization.DatawaveUser;
import datawave.security.authorization.JWTTokenHandler;
import datawave.security.evidence.JWTEvidence;
import org.apache.log4j.Logger;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;

import javax.inject.Inject;
import javax.net.ssl.X509KeyManager;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Collection;
import java.util.concurrent.TimeUnit;

public class JWTSecurityRealm implements SecurityRealm {
    
    private static final Logger log = Logger.getLogger(JWTSecurityRealm.class);
    
    @Inject
    private SSLContextInfo sslContextInfo;
    
    private JWTTokenHandler jwtTokenHandler;
    
    private void initJWTTokenHandler() {
        if (sslContextInfo == null) {
            log.trace("Injecting fields");
            BeanProvider.injectFields(this);
        }
        
        if(jwtTokenHandler == null) {
            log.trace("Initializing JWTTokenHandler");
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
                
                jwtTokenHandler = new JWTTokenHandler(certs[0], signingKey, 24, TimeUnit.HOURS, JWTTokenHandler.TtlMode.RELATIVE_TO_CURRENT_TIME, mapper);
            } catch (KeyStoreException e) {
                throw new RuntimeException("Failed to initialize JWTTokenHandler", e);
            }
        }
    }
    
    @Override
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) {
        return SupportLevel.UNSUPPORTED;
    }
    
    @Override
    public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) {
        return JWTEvidence.class.equals(evidenceType) ? SupportLevel.POSSIBLY_SUPPORTED : SupportLevel.UNSUPPORTED;
    }
    
    @Override
    public RealmIdentity getRealmIdentity(Evidence evidence) throws RealmUnavailableException {
        return SecurityRealm.super.getRealmIdentity(evidence);
    }
    
    private class JWTRealmIdentity implements RealmIdentity {
        
        private final JWTEvidence evidence;
        private Collection<DatawaveUser> users;
        
        public JWTRealmIdentity(Evidence evidence) {
            if(JWTEvidence.class.equals(evidence.getClass())) {
                this.evidence = (JWTEvidence) evidence;
            } else {
                this.evidence = null;
            }
        }
        
        @Override
        public Principal getRealmIdentityPrincipal() {
            if (this.users != null) {
                return new DatawavePrincipal(this.users);
            }
            return null;
        }
        
        @Override
        public AuthorizationIdentity getAuthorizationIdentity() {
            return new DatawaveAuthorizationIdentity(getRealmIdentityPrincipal());
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
            return JWTEvidence.class.equals(evidenceType) ? SupportLevel.POSSIBLY_SUPPORTED : SupportLevel.UNSUPPORTED;
        }
        
        @Override
        public boolean verifyEvidence(Evidence evidence) {
            return validateToken(evidence) != null;
        }
        
        @Override
        public boolean exists() {
            return getUsers() != null;
        }
        
        private void setUsers(Collection<DatawaveUser> users) {
            this.users = users;
        }
        
        private Collection<DatawaveUser> getUsers() {
            if (this.users == null) {
                validateToken(this.evidence);
            }
            return this.users;
        }
        
        private Collection<DatawaveUser> validateToken(Evidence evidence) {
            if(evidence instanceof JWTEvidence) {
                JWTEvidence tokenEvidence = (JWTEvidence) evidence;
                try {
                    initJWTTokenHandler();
                    setUsers(jwtTokenHandler.createUsersFromToken(tokenEvidence.getToken()));
                    return this.users;
                } catch (Exception e) {
                    log.debug("Failed to validate jwt token " + tokenEvidence.getToken(), e);
                }
            }
            return null;
        }
    }
}
