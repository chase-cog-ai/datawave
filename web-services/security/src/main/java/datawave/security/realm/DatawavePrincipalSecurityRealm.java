package datawave.security.realm;

import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.realm.CacheableSecurityRealm;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.event.RealmEvent;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;

import java.security.Principal;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Function;

public class DatawavePrincipalSecurityRealm implements CacheableSecurityRealm {
    
    private X509CertificateVerifier verifier;
    private boolean trustedHeaderLogin;
    private boolean jwtHeaderLogin;
    String disallowlistUserRole;
    Set<String> requiredRoles;
    Set<String> directRoles;
    
    public DatawavePrincipalSecurityRealm(X509CertificateVerifier verifier, String oscpLevel, boolean trustedHeaderLogin, boolean jwtHeaderLogin,
                    String disallowlistUserRole, Set<String>requiredRoles, Set<String> directRoles) {
        
    }
    
    @Override
    public RealmIdentity getRealmIdentity(Principal principal) throws RealmUnavailableException {
        return CacheableSecurityRealm.super.getRealmIdentity(principal);
    }
    
    @Override
    public RealmIdentity getRealmIdentity(Evidence evidence) throws RealmUnavailableException {
        return CacheableSecurityRealm.super.getRealmIdentity(evidence);
    }
    
    @Override
    public RealmIdentity getRealmIdentity(Evidence evidence, Function<Principal,Principal> principalTransformer) throws RealmUnavailableException {
        return CacheableSecurityRealm.super.getRealmIdentity(evidence, principalTransformer);
    }
    
    @Override
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec)
                    throws RealmUnavailableException {
        return null;
    }
    
    @Override
    public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
        return null;
    }
    
    @Override
    public void handleRealmEvent(RealmEvent event) {
        CacheableSecurityRealm.super.handleRealmEvent(event);
    }
    
    @Override
    public void registerIdentityChangeListener(Consumer<Principal> listener) {
        // Do nothing.
    }
}
