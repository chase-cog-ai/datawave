package datawave.security.realm;

import org.apache.log4j.Logger;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;

import java.security.Principal;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Map;

public class ProxiedSSLSecurityRealm implements SecurityRealm {
    
    private static final Logger log = Logger.getLogger(ProxiedSSLSecurityRealm.class);
    
    static final String VERIFIER = "verifier";
    static final String OSCP_LEVEL = "oscpLevel";
    
    private X509CertificateVerifier verifier;
    private boolean usingDatawaveVerifier = false;
    
    public void initialize(Map<String,String> config) {
        log.debug("Initializing " + ProxiedSSLSecurityRealm.class.getName() + " with config=" + config);
        initVerifier(config.get(VERIFIER), config.get(OSCP_LEVEL));
    }
    
    /**
     * Initialize the verifier for this {@link DatawavePrincipalSecurityRealm}. If the verifierClassName is null, no change will occur.
     *
     * @param verifierClassName
     *            the class name of the verifier class
     * @param oscpLevel
     *            the oscp level to set, if the verifier is an instance of {@link DatawaveCertVerifier}
     */
    private void initVerifier(String verifierClassName, String oscpLevel) {
        // Check if a verifier was specified.
        if (verifierClassName != null) {
            try {
                // If so, instantiate a new instance of the verifier.
                ClassLoader loader = Thread.currentThread().getContextClassLoader();
                Class<?> verifierClass = loader.loadClass(verifierClassName);
                this.verifier = (X509CertificateVerifier) verifierClass.getDeclaredConstructor().newInstance();
            } catch (Throwable e) {
                log.debug("Could not instantiate X509CertificateVerifier", e);
                throw new IllegalArgumentException("Invalid verifier: " + verifierClassName, e);
            }
            
            // If the verifier is an instance of DatawaveCertVerifier, update its logger and oscp level of the verifier.
            if (this.verifier instanceof DatawaveCertVerifier) {
                ((DatawaveCertVerifier) this.verifier).setLogger(log);
                try {
                    ((DatawaveCertVerifier) this.verifier).setOcspLevel(oscpLevel);
                } catch (Throwable e) {
                    log.debug("Could not set oscp level of verifier", e);
                    throw new IllegalArgumentException("Invalid oscpLevel: " + oscpLevel, e);
                }
                this.usingDatawaveVerifier = true;
            }
        }
    }
    
    @Override
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) {
        return SupportLevel.UNSUPPORTED;
    }
    
    @Override
    public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) {
        return SupportLevel.POSSIBLY_SUPPORTED;
    }
    
    private class ProxiedSSLRealmIdentity implements RealmIdentity {
        
        @Override
        public Principal getRealmIdentityPrincipal() {
            return null;
        }
        
        @Override
        public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) {
            return null;
        }
        
        @Override
        public <C extends Credential> C getCredential(Class<C> credentialType) {
            return null;
        }
        
        @Override
        public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) {
            return null;
        }
        
        @Override
        public boolean verifyEvidence(Evidence evidence) {
            return false;
        }
        
        @Override
        public boolean exists() {
            return false;
        }
    }
}
