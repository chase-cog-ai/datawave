package datawave.security.realm;

import datawave.security.authorization.SubjectIssuerDNPair;
import datawave.security.util.DnUtils;
import org.apache.commons.lang3.builder.CompareToBuilder;
import org.wildfly.security.credential.Credential;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Elytron version of DatawaveCredential to utilize with credential callbacks.
 */
public class DatawaveCredential implements Credential, Comparable<DatawaveCredential> {
    private X509Certificate certificate;
    private String userName;
    private List<SubjectIssuerDNPair> entities = new ArrayList<>();
    private String jwtToken;
    
    /**
     * Constructs a {@link datawave.security.auth.DatawaveCredential} using only DN information. This means there is no supplied certificate, and this credential will only be trusted
     * if the {@link datawave.security.login.DatawavePrincipalLoginModule} is configured with trusted header login (i.e., it is configured to trust the incoming
     * DN information without a supplied certificate).
     *
     * @param subjectDN
     *            the subject DN of the calling entity's certificate
     * @param issuerDN
     *            the issuer DN of the calling entity's certificate
     * @param proxiedSubjects
     *            any additional subject DNs (in the form &lt;DN&gt;&lt;DN&gt;...) indicating a chain of proxied users the calling entity represents
     * @param proxiedIssuers
     *            any additional issuer DNs (in the form &lt;DN&gt;&lt;DN&gt;...), one per subject listed in {@code proxiedSubjects}
     */
    public DatawaveCredential(String subjectDN, String issuerDN, String proxiedSubjects, String proxiedIssuers) {
        extractEntities(subjectDN, issuerDN, proxiedSubjects, proxiedIssuers);
    }
    
    /**
     * Constructs a {@link datawave.security.auth.DatawaveCredential} using a certificate. The certificate is fully trusted to identify the calling entity.
     *
     * @param certificate
     *            the {@link X509Certificate} that represents the calling entity
     * @param proxiedSubjects
     *            any additional subject DNs (in the form &lt;DN&gt;&lt;DN&gt;...) indicating a chain of proxied users the calling entity represents
     * @param proxiedIssuers
     *            any additional issuer DNs (in the form &lt;DN&gt;&lt;DN&gt;...), one per subject listed in {@code proxiedSubjects}
     */
    public DatawaveCredential(X509Certificate certificate, String proxiedSubjects, String proxiedIssuers) {
        this.certificate = certificate;
        String subjectDN = certificate.getSubjectDN().getName();
        String issuerDN = certificate.getIssuerDN().getName();
        extractEntities(subjectDN, issuerDN, proxiedSubjects, proxiedIssuers);
    }
    
    /**
     * Copy constructor
     * @param other the other credential
     */
    private DatawaveCredential(DatawaveCredential other) {
        this.certificate = other.certificate;
        this.userName = other.userName;
        this.entities = other.entities == null ? Collections.emptyList() : new ArrayList<>(other.entities);
        this.jwtToken = other.jwtToken;
    }
    
    public DatawaveCredential(String jwtToken) {
        this.userName = jwtToken;
        this.jwtToken = jwtToken;
    }
    
    private void extractEntities(String subjectDN, String issuerDN, String proxiedSubjects, String proxiedIssuers) {
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
        entities.add(SubjectIssuerDNPair.of(subjectDN, issuerDN));
        userName = DnUtils.buildNormalizedProxyDN(subjectDN, issuerDN, proxiedSubjects, proxiedIssuers);
    }
    
    public void pruneEntities(Set<String> entitiesToPrune) {
        Set<String> normalizedEntities = entitiesToPrune.stream().map(e -> e.toLowerCase()).collect(Collectors.toSet());
        entities = entities.stream().filter(e -> !normalizedEntities.contains(e.subjectDN().toLowerCase())).collect(Collectors.toList());
        userName = DnUtils.buildNormalizedProxyDN(entities);
    }
    
    public String getUserName() {
        return userName;
    }
    
    public List<SubjectIssuerDNPair> getEntities() {
        return Collections.unmodifiableList(entities);
    }
    
    public X509Certificate getCertificate() {
        return certificate;
    }
    
    public String getJwtToken() {
        return jwtToken;
    }
    
    @Override
    public int compareTo(DatawaveCredential o) {
        return new CompareToBuilder().append(userName, o.getUserName()).append(jwtToken, o.getJwtToken()).toComparison();
    }
    
    @Override
    public String toString() {
        return "DatawaveCredential[userName=\"" + getUserName() + "\", certificate=\"" + getCertificate() + "\"]";
    }
    
    @Override
    public Credential clone() {
        return null;
    }
}
