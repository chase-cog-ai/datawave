package datawave.security.evidence;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Collection;

import org.apache.log4j.Logger;
import org.wildfly.security.evidence.Evidence;

import com.google.common.base.Preconditions;

import datawave.security.SSLContextInfo;
import datawave.security.authorization.AuthorizationException;
import datawave.security.authorization.DatawaveUser;
import datawave.security.authorization.DatawaveUserService;
import datawave.security.cert.DatawaveCertVerifier;
import datawave.security.cert.X509CertificateVerifier;

/**
 * {@link EvidenceIdentityProvider} implementation for SSL cert authentication.
 */
public class ProxiedX509CertificateEvidenceIdentityProvider implements EvidenceIdentityProvider {

    private static final Logger log = Logger.getLogger(ProxiedX509CertificateEvidenceIdentityProvider.class);

    private final DatawaveUserService userService;
    private final SSLContextInfo sslContextInfo;
    private final X509CertificateVerifier certVerifier;

    public ProxiedX509CertificateEvidenceIdentityProvider(DatawaveUserService userService, SSLContextInfo sslContextInfo, X509CertificateVerifier certVerifier)
                    throws IllegalArgumentException {
        this.userService = userService;
        this.sslContextInfo = sslContextInfo;
        this.certVerifier = certVerifier;
    }

    @Override
    public boolean canProvideIdentityFrom(Class<? extends Evidence> evidenceType) {
        return ProxiedX509CertificateEvidence.class.equals(evidenceType);
    }

    @Override
    public EvidenceIdentity getIdentity(Evidence evidence) throws AuthorizationException {
        Preconditions.checkNotNull(evidence, "Evidence may not be null");
        Preconditions.checkArgument(canProvideIdentityFrom(evidence.getClass()), "Evidence type " + evidence.getClass().getName() + " is not supported");

        ProxiedX509CertificateEvidence certificateEvidence = (ProxiedX509CertificateEvidence) evidence;
        // Validate the provided certificate.
        if (isValidCertificate(certificateEvidence.getCertificate())) {
            Collection<DatawaveUser> users = this.userService.lookup(certificateEvidence.getEntities());
            if (users != null && !users.isEmpty()) {
                return new EvidenceIdentity(users);
            } else {
                log.trace("User service returned no users for certificate " + certificateEvidence.getCertificate());
            }
        } else {
            if (log.isTraceEnabled()) {
                log.trace("Certificate is not valid: " + certificateEvidence.getCertificate());
            }
        }

        return null;
    }

    /**
     * Return whether the given certificate is considered valid.
     *
     * @param certificate
     *            the certificate to validate
     * @return true if the certificate is valid, or false otherwise
     */
    private boolean isValidCertificate(X509Certificate certificate) {
        if (certVerifier != null) {
            KeyStore keyStore = this.sslContextInfo.getKeyStore();
            KeyStore trustStore = this.sslContextInfo.getTrustStore();
            if (trustStore != null) {
                trustStore = keyStore;
            }
            String alias = certificate.getIssuerX500Principal().getName();
            if (certVerifier instanceof DatawaveCertVerifier && !((DatawaveCertVerifier) certVerifier).isIssuerSupported(alias, trustStore)) {
                return false;
            }
            return certVerifier.verify(certificate, alias, keyStore, trustStore);
        } else {
            return true;
        }
    }
}
