package datawave.security.realm;

import java.security.Principal;
import java.security.spec.AlgorithmParameterSpec;

import datawave.security.authorization.DatawavePrincipal;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;

public class DatawaveRealmIdentity implements RealmIdentity {

    private DatawavePrincipal principal;
    
    @Override
    public Principal getRealmIdentityPrincipal() {
        return null;
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec)
                    throws RealmUnavailableException {
        return null;
    }

    @Override
    public <C extends Credential> C getCredential(Class<C> credentialType) throws RealmUnavailableException {
        return null;
    }

    @Override
    public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
        return null;
    }

    @Override
    public boolean verifyEvidence(Evidence evidence) throws RealmUnavailableException {
        return false;
    }

    @Override
    public boolean exists() throws RealmUnavailableException {
        return false;
    }
}
