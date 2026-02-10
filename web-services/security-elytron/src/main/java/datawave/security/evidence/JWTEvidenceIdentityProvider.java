package datawave.security.evidence;

import java.util.Collection;

import org.apache.log4j.Logger;
import org.wildfly.security.evidence.Evidence;

import com.google.common.base.Preconditions;

import datawave.security.authorization.DatawaveUser;
import datawave.security.authorization.JWTTokenHandler;

/**
 * {@link EvidenceIdentityProvider} implementation for JWT authentication.
 */
public class JWTEvidenceIdentityProvider implements EvidenceIdentityProvider {

    private static final Logger log = Logger.getLogger(JWTEvidenceIdentityProvider.class);

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
        if (users != null && !users.isEmpty()) {
            return new EvidenceIdentity(users);
        } else {
            if (log.isTraceEnabled()) {
                log.trace("No users found for jwt token " + jwtEvidence.getToken());
            }
            return null;
        }
    }
}
