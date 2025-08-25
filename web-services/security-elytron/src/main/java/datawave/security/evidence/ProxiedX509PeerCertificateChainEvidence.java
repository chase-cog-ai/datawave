package datawave.security.evidence;


import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.StringJoiner;

public class ProxiedX509PeerCertificateChainEvidence extends PrunableEvidence {
    
    private final X509Certificate certificate;
    private final String proxiedEntities;
    private final String proxiedIssuers;
    
    public ProxiedX509PeerCertificateChainEvidence(X509Certificate certificate, String proxiedEntities, String proxiedIssuers) {
        this.certificate = certificate;
        this.proxiedEntities = proxiedEntities;
        this.proxiedIssuers = proxiedIssuers;
        extractEntities(certificate.getSubjectDN().getName(), certificate.getIssuerDN().getName(), proxiedEntities, proxiedIssuers);
    }
    
    public X509Certificate getCertificate() {
        return certificate;
    }
    
    public String getProxiedEntities() {
        return proxiedEntities;
    }
    
    public String getProxiedIssuers() {
        return proxiedIssuers;
    }
    
    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        if (!super.equals(o)) {
            return false;
        }
        ProxiedX509PeerCertificateChainEvidence evidence = (ProxiedX509PeerCertificateChainEvidence) o;
        return Objects.equals(certificate, evidence.certificate) && Objects.equals(proxiedEntities, evidence.proxiedEntities) && Objects.equals(proxiedIssuers,
                        evidence.proxiedIssuers);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), certificate, proxiedEntities, proxiedIssuers);
    }
    
    @Override
    public String toString() {
        // @formatter:off
        return new StringJoiner(", ", ProxiedX509PeerCertificateChainEvidence.class.getSimpleName() + "[", "]")
                        .add("certificate=" + certificate)
                        .add("proxiedEntities='" + proxiedEntities + "'")
                        .add("proxiedIssuers='" + proxiedIssuers + "'")
                        .add("username='" + username + "'")
                        .add("entities=" + entities).toString();
        // @formatter:on
    }
}
