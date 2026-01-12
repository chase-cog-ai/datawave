package datawave.security.evidence;

import java.util.Collection;

import org.wildfly.security.evidence.Evidence;

import com.google.common.base.Preconditions;

import datawave.security.authorization.AuthorizationException;
import datawave.security.authorization.DatawaveUser;
import datawave.security.authorization.DatawaveUserService;

/**
 * {@link EvidenceIdentityProvider} implementation for trusted header authentication.
 */
public class TrustedHeaderEvidenceIdentityProvider implements EvidenceIdentityProvider {

    private final DatawaveUserService userService;

    public TrustedHeaderEvidenceIdentityProvider(DatawaveUserService userService) {
        this.userService = userService;
    }

    @Override
    public boolean canProvideIdentityFrom(Class<? extends Evidence> evidenceType) {
        return TrustedHeaderEvidence.class.equals(evidenceType);
    }

    @Override
    public EvidenceIdentity getIdentity(Evidence evidence) {
        Preconditions.checkNotNull(evidence, "Evidence may not be null");
        Preconditions.checkArgument(canProvideIdentityFrom(evidence.getClass()), "Evidence type " + evidence.getClass().getName() + " is not supported");

        TrustedHeaderEvidence trustedHeaderEvidence = (TrustedHeaderEvidence) evidence;

        try {
            Collection<DatawaveUser> users = this.userService.lookup(trustedHeaderEvidence.getEntities());
            return new EvidenceIdentity(users);
        } catch (AuthorizationException e) {
            throw new RuntimeException(e);
        }
    }
}
