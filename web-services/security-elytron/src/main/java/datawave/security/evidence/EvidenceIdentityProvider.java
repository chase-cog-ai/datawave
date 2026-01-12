package datawave.security.evidence;

import org.wildfly.security.evidence.Evidence;

/**
 * Represents a provider that is capable of identifying a user identity associated with a particular type of evidence.
 */
public interface EvidenceIdentityProvider {

    /**
     * Return whether this provider supports attempting to provide an identity for the given evidence type.
     *
     * @param evidenceType
     *            the evidence type
     * @return true if this provider supports providing an identity for the given evidence type, or false otherwise
     */
    boolean canProvideIdentityFrom(Class<? extends Evidence> evidenceType);

    /**
     * Returns the user identity information associated with the given evidence, or null if no identity could be found.
     *
     * @param evidence
     *            the evidence
     * @return the identity, possibly null
     */
    EvidenceIdentity getIdentity(Evidence evidence);
}
