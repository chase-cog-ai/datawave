package datawave.security.evidence;

import com.google.common.base.Preconditions;
import datawave.security.authorization.DatawaveUser;
import datawave.security.authorization.JWTTokenHandler;
import org.wildfly.security.evidence.Evidence;

import java.util.Collection;

/**
 * {@link EvidenceIdentityProvider} implementation for JWT authentication.
 */
public class JWTEvidenceIdentityProvider implements EvidenceIdentityProvider {
    
    private final JWTTokenHandler jwtTokenHandler;
    
    public JWTEvidenceIdentityProvider(JWTTokenHandler jwtTokenHandler) {
        Preconditions.checkNotNull(jwtTokenHandler, "Parameter jwtTokenHandler may not be null");
        this.jwtTokenHandler = jwtTokenHandler;
    }
    
    @Override
    public boolean canProvideIdentityFrom(Class<? extends Evidence> evidenceType) {
        return JWTEvidence.class.equals(evidenceType);
    }
    
    @Override
    public EvidenceIdentity getIdentity(Evidence evidence) {
        Preconditions.checkNotNull(evidence, "Evidence may not be null");
        Preconditions.checkArgument(canProvideIdentityFrom(evidence.getClass()), "Evidence type " + evidence.getClass().getName() + " is not supported");
        
        JWTEvidence jwtEvidence = (JWTEvidence) evidence;
        Collection<DatawaveUser> users = jwtTokenHandler.createUsersFromToken(jwtEvidence.getToken());
        return new EvidenceIdentity(users);
    }
}
