package datawave.security.realm;

import datawave.configuration.spring.BeanProvider;
import datawave.security.authorization.DatawavePrincipal;
import datawave.security.authorization.DatawaveUser;
import datawave.security.authorization.DatawaveUserService;
import datawave.security.evidence.TrustedHeaderEvidence;
import org.apache.log4j.Logger;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;

import javax.inject.Inject;
import java.security.Principal;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Collection;
import java.util.Objects;

public class TrustedHeaderSecurityRealm implements SecurityRealm {
    
    private static final Logger log = Logger.getLogger(TrustedHeaderSecurityRealm.class);
    
    @Inject
    private DatawaveUserService userService;
    
    @Override
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) {
        return SupportLevel.UNSUPPORTED;
    }
    
    @Override
    public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) {
        Objects.requireNonNull(evidenceType, "evidenceType cannot be null");
        return evidenceType.equals(TrustedHeaderEvidence.class) ? SupportLevel.POSSIBLY_SUPPORTED : SupportLevel.UNSUPPORTED;
    }
    
    @Override
    public RealmIdentity getRealmIdentity(Evidence evidence) {
        return new TrustedHeaderRealmIdentity(evidence);
    }
    
    private void initUserService() {
        if(userService == null) {
            BeanProvider.injectFields(this);
        }
    }
    
    private class TrustedHeaderRealmIdentity implements RealmIdentity {
        
        private final TrustedHeaderEvidence evidence;
        private Collection<DatawaveUser> users;
        
        public TrustedHeaderRealmIdentity(Evidence evidence) {
            if(evidence instanceof TrustedHeaderEvidence) {
                this.evidence = (TrustedHeaderEvidence) evidence;
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
            return TrustedHeaderEvidence.class.equals(evidenceType) ? SupportLevel.POSSIBLY_SUPPORTED : SupportLevel.UNSUPPORTED;
        }
        
        @Override
        public boolean verifyEvidence(Evidence evidence) {
            return validateHeaders(evidence) != null;
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
                validateHeaders(this.evidence);
            }
            return this.users;
        }
        
        private Collection<DatawaveUser> validateHeaders(Evidence evidence) {
            if(evidence instanceof TrustedHeaderEvidence) {
                TrustedHeaderEvidence headerEvidence = (TrustedHeaderEvidence) evidence;
                try {
                    initUserService();
                    setUsers(userService.lookup(headerEvidence.getEntities()));
                    return this.users;
                } catch (Exception e) {
                    log.debug("Failed to validate trusted headers username=" + headerEvidence.getUsername() + ", entities=" + headerEvidence.getEntities() , e);
                }
            }
            return null;
        }
    }
}
