package datawave.security.evidence;

import java.util.StringJoiner;

public class TrustedHeaderEvidence extends PrunableEvidence {
    
    public TrustedHeaderEvidence(String subjectDn, String issuerDn, String proxiedSubjects, String proxiedIssuers) {
        extractEntities(subjectDn, issuerDn, proxiedSubjects, proxiedIssuers);
    }
    
    
    
    @Override
    public String toString() {
        // @formatter:off
        return new StringJoiner(", ", TrustedHeaderEvidence.class.getSimpleName() + "[", "]")
                        .add("username='" + username + "'")
                        .add("entities=" + entities)
                        .toString();
        // @formatter:on
    }
}
