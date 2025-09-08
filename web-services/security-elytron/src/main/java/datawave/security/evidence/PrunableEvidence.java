package datawave.security.evidence;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.wildfly.security.evidence.Evidence;

import datawave.security.authorization.SubjectIssuerDNPair;
import datawave.security.util.DnUtils;

public abstract class PrunableEvidence implements Evidence {

    protected String username;
    protected List<SubjectIssuerDNPair> entities;

    protected void extractEntities(String subjectDn, String issuerDn, String proxiedSubjects, String proxiedIssuers) {
        if (proxiedSubjects != null) {
            String[] subjects = DnUtils.splitProxiedDNs(proxiedSubjects, true);
            if (proxiedIssuers == null)
                throw new IllegalArgumentException("Proxied issuers must be supplied if proxied subjects are supplied");
            String[] issuers = DnUtils.splitProxiedDNs(proxiedIssuers, true);
            if (subjects.length != issuers.length)
                throw new IllegalArgumentException("Proxied subjects and issuers don't match up. Subjects=" + proxiedSubjects + ", Issuers=" + proxiedIssuers);

            for (int i = 0; i < subjects.length; ++i) {
                entities.add(SubjectIssuerDNPair.of(subjects[i], issuers[i]));
            }
        }
        entities.add(SubjectIssuerDNPair.of(subjectDn, issuerDn));
        username = DnUtils.buildNormalizedProxyDN(subjectDn, issuerDn, proxiedSubjects, proxiedIssuers);
    }

    public void pruneEntities(Collection<String> entitiesToPrune) {
        Set<String> normalizedEntities = entitiesToPrune.stream().map(String::toLowerCase).collect(Collectors.toSet());
        this.entities = entities.stream().filter(e -> !normalizedEntities.contains(e.subjectDN().toLowerCase())).collect(Collectors.toList());
        this.username = DnUtils.buildNormalizedProxyDN(entities);
    }

    public String getUsername() {
        return username;
    }

    public List<SubjectIssuerDNPair> getEntities() {
        return List.copyOf(entities);
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        PrunableEvidence that = (PrunableEvidence) o;
        return Objects.equals(username, that.username) && Objects.equals(entities, that.entities);
    }

    @Override
    public int hashCode() {
        return Objects.hash(username, entities);
    }
}
