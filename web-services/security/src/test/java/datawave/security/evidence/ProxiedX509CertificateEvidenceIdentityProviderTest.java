package datawave.security.evidence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.InputStream;
import java.security.Principal;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.evidence.Evidence;

import datawave.security.SSLContextInfo;
import datawave.security.authorization.AuthorizationException;
import datawave.security.authorization.DatawaveUser;
import datawave.security.authorization.DatawaveUserService;
import datawave.security.cert.X509CertificateVerifier;
import datawave.security.util.DnUtils;

class ProxiedX509CertificateEvidenceIdentityProviderTest {

    private static final String pkcs12KeystorePath = "/datwave-server-keystore.p12";
    private static final String pkcs12TruststorePath = "/datwave-server-truststore.p12";
    private static final String pkcs12CertPath = "/testUser.p12";

    private ProxiedX509CertificateEvidenceIdentityProvider provider;

    private DatawaveUserService userService;
    private SSLContextInfo sslContextInfo;
    private X509CertificateVerifier certificateVerifier;

    private String originalSubjectDnPattern;

    @BeforeEach
    void setUp() {
        originalSubjectDnPattern = System.getProperty(DnUtils.SUBJECT_DN_PATTERN_PROPERTY);
        System.setProperty(DnUtils.SUBJECT_DN_PATTERN_PROPERTY, ".*ou=server.*");

        userService = mock(DatawaveUserService.class);
        sslContextInfo = mock(SSLContextInfo.class);
        certificateVerifier = mock(X509CertificateVerifier.class);

        provider = new ProxiedX509CertificateEvidenceIdentityProvider(userService, sslContextInfo, certificateVerifier);
    }

    @AfterEach
    void tearDown() {
        if (originalSubjectDnPattern != null) {
            System.setProperty(DnUtils.SUBJECT_DN_PATTERN_PROPERTY, originalSubjectDnPattern);
        } else {
            System.clearProperty(DnUtils.SUBJECT_DN_PATTERN_PROPERTY);
        }
    }

    /**
     * Verify that {@link ProxiedX509CertificateEvidenceIdentityProvider#canProvideIdentityFrom(Class)} can provide evidence for
     * {@link ProxiedX509CertificateEvidence} instances, but not other types.
     */
    @Test
    void testCanProvideIdentityFrom() {
        assertThat(provider.canProvideIdentityFrom(ProxiedX509CertificateEvidence.class)).isTrue();
        assertThat(provider.canProvideIdentityFrom(JWTEvidence.class)).isFalse();
        assertThat(provider.canProvideIdentityFrom(TrustedHeaderEvidence.class)).isFalse();
    }

    /**
     * Verify that {@link ProxiedX509CertificateEvidenceIdentityProvider#getIdentity(Evidence)} throws an exception when given null evidence.
     */
    @Test
    void testGetIdentityGivenNullEvidence() {
        assertThatThrownBy(() -> provider.getIdentity(null)).isInstanceOf(NullPointerException.class).hasMessageContaining("Evidence may not be null");
    }

    /**
     * Verify that {@link ProxiedX509CertificateEvidenceIdentityProvider#getIdentity(Evidence)} throws an exception when given evidence that is not an instance
     * of {@link ProxiedX509CertificateEvidence}.
     */
    @Test
    void testGetIdentityGivenNonProxiedX509CertificateEvidence() {
        Evidence otherEvidence = mock(Evidence.class);
        assertThatThrownBy(() -> provider.getIdentity(otherEvidence)).isInstanceOf(IllegalArgumentException.class)
                        .hasMessageContaining("Evidence type " + otherEvidence.getClass().getName() + " is not supported");
    }

    /**
     * Verify that {@link ProxiedX509CertificateEvidenceIdentityProvider#getIdentity(Evidence)} returns null when the certificate verifier is null and the user
     * service returns null.
     */
    @Test
    void testGetIdentityGivenNullVerifierAndNullUsersReturned() throws AuthorizationException {
        provider = new ProxiedX509CertificateEvidenceIdentityProvider(userService, sslContextInfo, null);

        // Mock up the certificate.
        X509Certificate certificate = mock(X509Certificate.class);
        Principal subjectPrincipal = mock(Principal.class);
        when(certificate.getSubjectDN()).thenReturn(subjectPrincipal);
        when(subjectPrincipal.getName()).thenReturn("cn=john q. doe, c=us, o=my org, ou=my dept");

        Principal issuerPrincipal = mock(Principal.class);
        when(certificate.getIssuerDN()).thenReturn(issuerPrincipal);
        when(issuerPrincipal.getName()).thenReturn("cn=issuer, c=us, o=my org, ou=my dept");

        String proxiedEntities = "cn=proxiedServer01, c=us, o=my org, ou=my dept<cn=proxiedServer01, c=us, o=my org, ou=my dept>";
        String proxiedIssuers = "cn=proxiedIssuer01, c=us, o=my org, ou=my dept<cn=proxiedIssuer02, c=us, o=my org, ou=my dept>";

        // Mock up the user service behavior.
        ProxiedX509CertificateEvidence evidence = new ProxiedX509CertificateEvidence(certificate, proxiedEntities, proxiedIssuers);

        when(userService.lookup(any())).thenReturn(null);

        // Assert the identity.
        assertThat(provider.getIdentity(evidence)).isNull();
    }

    /**
     * Verify that {@link ProxiedX509CertificateEvidenceIdentityProvider#getIdentity(Evidence)} returns null when the certificate verifier is null and the user
     * service returns an empty collection.
     */
    @Test
    void testGetIdentityGivenNullVerifierAndEmptyUsersReturned() throws AuthorizationException {
        provider = new ProxiedX509CertificateEvidenceIdentityProvider(userService, sslContextInfo, null);

        // Mock up the certificate.
        X509Certificate certificate = mock(X509Certificate.class);
        Principal subjectPrincipal = mock(Principal.class);
        when(certificate.getSubjectDN()).thenReturn(subjectPrincipal);
        when(subjectPrincipal.getName()).thenReturn("cn=john q. doe, c=us, o=my org, ou=my dept");

        Principal issuerPrincipal = mock(Principal.class);
        when(certificate.getIssuerDN()).thenReturn(issuerPrincipal);
        when(issuerPrincipal.getName()).thenReturn("cn=issuer, c=us, o=my org, ou=my dept");

        String proxiedEntities = "cn=proxiedServer01, c=us, o=my org, ou=my dept<cn=proxiedServer01, c=us, o=my org, ou=my dept>";
        String proxiedIssuers = "cn=proxiedIssuer01, c=us, o=my org, ou=my dept<cn=proxiedIssuer02, c=us, o=my org, ou=my dept>";

        ProxiedX509CertificateEvidence evidence = new ProxiedX509CertificateEvidence(certificate, proxiedEntities, proxiedIssuers);

        // Mock up the user service behavior.
        when(userService.lookup(any())).thenReturn(new HashSet<>());

        // Assert the identity.
        assertThat(provider.getIdentity(evidence)).isNull();
    }

    /**
     * Verify that {@link ProxiedX509CertificateEvidenceIdentityProvider#getIdentity(Evidence)} returns non-null evidence when the certificate verifier is null
     * and the user service returns a non-empty collection.
     */
    @Test
    void testGetIdentityGivenNullVerifierAndUsersReturned() throws AuthorizationException {
        provider = new ProxiedX509CertificateEvidenceIdentityProvider(userService, sslContextInfo, null);

        // Mock up the certificate.
        X509Certificate certificate = mock(X509Certificate.class);
        Principal subjectPrincipal = mock(Principal.class);
        when(certificate.getSubjectDN()).thenReturn(subjectPrincipal);
        when(subjectPrincipal.getName()).thenReturn("cn=john q. doe, c=us, o=my org, ou=my dept");

        Principal issuerPrincipal = mock(Principal.class);
        when(certificate.getIssuerDN()).thenReturn(issuerPrincipal);
        when(issuerPrincipal.getName()).thenReturn("cn=issuer, c=us, o=my org, ou=my dept");

        String proxiedEntities = "cn=proxiedServer01, c=us, o=my org, ou=my dept<cn=proxiedServer01, c=us, o=my org, ou=my dept>";
        String proxiedIssuers = "cn=proxiedIssuer01, c=us, o=my org, ou=my dept<cn=proxiedIssuer02, c=us, o=my org, ou=my dept>";

        ProxiedX509CertificateEvidence evidence = new ProxiedX509CertificateEvidence(certificate, proxiedEntities, proxiedIssuers);

        // Mock up the user service behavior.
        Set<DatawaveUser> users = new HashSet<>();
        users.add(mock(DatawaveUser.class));
        when(userService.lookup(evidence.getEntities())).thenReturn(users);

        // Obtain the identity for the evidence.
        EvidenceIdentity identity = provider.getIdentity(evidence);

        // Assert the identity.
        assertThat(identity).isNotNull();
        assertThat(identity.getAttributes()).isEqualTo(Attributes.EMPTY);
        assertThat(identity.getUsers()).hasSize(1).containsAll(users);
    }

    private X509Certificate loadX509Certificate(String path) throws Exception {
        try (InputStream is = getClass().getResourceAsStream(path)) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(is);
        }
    }
}
