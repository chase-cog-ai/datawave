package datawave.security.evidence;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Collection;

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
    public EvidenceIdentity getIdentity(Evidence evidence) {
        Preconditions.checkNotNull(evidence, "Evidence may not be null");
        Preconditions.checkArgument(canProvideIdentityFrom(evidence.getClass()), "Evidence type " + evidence.getClass().getName() + " is not supported");

        ProxiedX509CertificateEvidence certificateEvidence = (ProxiedX509CertificateEvidence) evidence;
        // Validate the provided certificate.
        if (isValidCertificate(certificateEvidence.getCertificate())) {
            try {
                Collection<DatawaveUser> users = this.userService.lookup(certificateEvidence.getEntities());
                return new EvidenceIdentity(users);
            } catch (AuthorizationException e) {
                throw new RuntimeException(e);
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
        KeyStore keyStore = this.sslContextInfo.getKeyStore();
        KeyStore trustStore = this.sslContextInfo.getTrustStore();
        if (trustStore != null) {
            trustStore = keyStore;
        }

        if (certVerifier != null) {
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
