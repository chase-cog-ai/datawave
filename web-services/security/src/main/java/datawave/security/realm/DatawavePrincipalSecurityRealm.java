package datawave.security.realm;

import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import javax.inject.Inject;
import javax.net.ssl.KeyManager;
import javax.net.ssl.X509KeyManager;

import org.apache.log4j.Logger;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;

import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.guava.GuavaModule;
import com.fasterxml.jackson.module.jaxb.JaxbAnnotationModule;

import datawave.configuration.spring.BeanProvider;
import datawave.security.authorization.DatawaveUserService;
import datawave.security.authorization.JWTTokenHandler;
import datawave.util.StringUtils;

public class DatawavePrincipalSecurityRealm implements SecurityRealm {

    static final String VERIFIER = "verifier";
    static final String OSCP = "oscpLevel";
    static final String TRUSTED_HEADER_LOGIN = "trustedHeaderLogin";
    static final String JWT_HEADER_LOGIN = "jwtHeaderLogin";
    static final String DISALLOWLIST_USER_ROLE = "disallowlistUserRole";
    static final String DIRECT_ROLES = "directRoles";

    static final String ROLE_AUTHORIZED_USER = "AuthorizedUser";
    static final String ROLE_AUTHORIZED_SERVER = "AuthorizedServer";
    static final String ROLE_AUTHORIZED_QUERY_SERVER = "AuthorizedQueryServer";
    static final String ROLE_AUTHORIZED_PROXIED_SERVER = "AuthorizedProxiedServer";

    private static final Set<String> defaultRequiredRoles = Set.of(ROLE_AUTHORIZED_USER, ROLE_AUTHORIZED_SERVER, ROLE_AUTHORIZED_QUERY_SERVER,
                    ROLE_AUTHORIZED_PROXIED_SERVER);
    private static final Set<String> defaultDirectRoles = Set.of(ROLE_AUTHORIZED_SERVER, ROLE_AUTHORIZED_QUERY_SERVER);

    private final Logger log;

    @Inject
    private DatawaveUserService datawaveUserService;

    private KeyStore serverKeyStore;
    private KeyStore serverTrustStore;
    private KeyManager serverKeyManager;

    private X509CertificateVerifier verifier;
    private boolean trustedHeaderLogin;
    private boolean jwtHeaderLogin;
    private String disallowlistUserRole;
    private Set<String> directRoles;
    private JWTTokenHandler jwtTokenHandler;
    private boolean trace;

    public DatawavePrincipalSecurityRealm() {
        log = Logger.getLogger(getClass());
    }

    /**
     * Initializes this security realm with the given configuration options.
     *
     * @param config
     *            the configuration
     */
    public void initialize(Map<String,String> config) {
        trace = log.isTraceEnabled();
        if (trace) {
            log.trace("enter: initialize(Map): config=" + config);
        }

        performFieldInjection();

        initVerifier(config.get(VERIFIER), config.get(OSCP));
        initTrustedHeaderLogin(config.get(TRUSTED_HEADER_LOGIN));
        initJwtHeaderLogin(config.get(JWT_HEADER_LOGIN));
        initDisallowlistUserRole(config.get(DISALLOWLIST_USER_ROLE));
        initDirectRoles(config.get(DIRECT_ROLES));
        initJWTTokenHandler();

        if (trace) {
            log.trace("exit: initialize(Map)" + config);
        }
    }

    /**
     * Inject any uninitialized CDI resources.
     */
    protected void performFieldInjection() {
        if (datawaveUserService == null) {
            BeanProvider.injectFields(this);
        }
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
                verifier = (X509CertificateVerifier) verifierClass.getDeclaredConstructor().newInstance();
            } catch (Throwable e) {
                if (trace) {
                    log.trace("Could not instantiate X509CertificateVerifier", e);
                }
                throw new IllegalArgumentException("Invalid verifier: " + verifierClassName, e);
            }

            // If the verifier is an instance of DatawaveCertVerifier, update its logger and oscp level of the verifier.
            if (verifier instanceof DatawaveCertVerifier) {
                ((DatawaveCertVerifier) verifier).setLogger(log);
                try {
                    ((DatawaveCertVerifier) verifier).setOcspLevel(oscpLevel);
                } catch (Throwable e) {
                    if (trace) {
                        log.trace("Could not set oscp level of verifier", e);
                    }
                    throw new IllegalArgumentException("Invalid oscpLevel: " + oscpLevel, e);
                }
            }
        }
    }

    /**
     * Initialize the trustedHeaderLogin for this {@link DatawavePrincipalSecurityRealm}.
     *
     * @param trustedHeaderLogin
     *            the trusted header login
     */
    private void initTrustedHeaderLogin(String trustedHeaderLogin) {
        if (trustedHeaderLogin != null) {
            this.trustedHeaderLogin = Boolean.parseBoolean(trustedHeaderLogin);
        }
    }

    /**
     * Initialize the jwtHeaderLogin for this {@link DatawavePrincipalSecurityRealm}.
     *
     * @param jwtHeaderLogin
     *            the jwt header login
     */
    private void initJwtHeaderLogin(String jwtHeaderLogin) {
        if (jwtHeaderLogin != null) {
            this.jwtHeaderLogin = Boolean.parseBoolean(jwtHeaderLogin);
        }
    }

    /**
     * Initialize the disallowListUserRole for this {@link DatawavePrincipalSecurityRealm}. If the given value is blank, the role will be set to null.
     *
     * @param disallowlistUserRole
     *            the disallowlist user role
     */
    private void initDisallowlistUserRole(String disallowlistUserRole) {
        this.disallowlistUserRole = disallowlistUserRole != null && disallowlistUserRole.trim().isEmpty() ? null : disallowlistUserRole;
    }

    /**
     * Initialize the direct roles for this {@link DatawavePrincipalSecurityRealm} from a colon-delimited list of roles. If the given string is not null, the
     * roles will be cleared, and the new roles added. Otherwise, all default direct roles will be added.
     *
     * @param directRoles
     *            the direct roles
     */
    private void initDirectRoles(String directRoles) {
        if (directRoles != null) {
            this.directRoles.clear();
            this.directRoles.addAll(Arrays.asList(StringUtils.split(directRoles, ':', false)));
        } else {
            this.directRoles.addAll(defaultDirectRoles);
        }
    }

    private void initJWTTokenHandler() {
        try {
            // @formatter:off
            ObjectMapper mapper = JsonMapper.builder()
                            .enable(MapperFeature.USE_WRAPPER_NAME_AS_PROPERTY_NAME)
                            .addModule(new GuavaModule())
                            .addModule(new JaxbAnnotationModule())
                            .build();
            // @formatter:on

            String alias = serverKeyStore.aliases().nextElement();
            X509KeyManager keyManager = (X509KeyManager) serverKeyManager;
            X509Certificate[] certs = keyManager.getCertificateChain(alias);
            Key signingKey = keyManager.getPrivateKey(alias);

            jwtTokenHandler = new JWTTokenHandler(certs[0], signingKey, 24, TimeUnit.HOURS, JWTTokenHandler.TtlMode.RELATIVE_TO_CURRENT_TIME, mapper);
        } catch (KeyStoreException e) {
            if (trace) {
                log.trace("Could not initialize JWTTokenHandler", e);
            }
            throw new RuntimeException(e);
        } catch (Exception e) {
            if (trace) {
                log.trace("Could not initialize JWTTokenHandler", e);
            }
            throw e;
        }

    }

    @Override
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) {
        if (trace) {
            log.trace("enter: getCredentialAcquireSupport(" + credentialType + ", " + algorithmName + ", " + parameterSpec + ")");
        }
        log.trace("exit: getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec)");
        return SupportLevel.POSSIBLY_SUPPORTED;
    }

    @Override
    public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) {
        if (trace) {
            log.trace("enter: getEvidenceVerifySupport(" + evidenceType + ", " + algorithmName + ")");
        }
        log.trace("exit: getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName)");
        return SupportLevel.POSSIBLY_SUPPORTED;
    }
}
