package datawave.security.evidence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.evidence.Evidence;

import datawave.security.authorization.AuthorizationException;
import datawave.security.authorization.DatawaveUser;
import datawave.security.authorization.DatawaveUserService;
import datawave.security.util.DnUtils;

class TrustedHeaderEvidenceIdentityProviderTest {

    private String originalSubjectDnPattern;

    @BeforeEach
    void setUp() {
        originalSubjectDnPattern = System.getProperty(DnUtils.SUBJECT_DN_PATTERN_PROPERTY);
        System.setProperty(DnUtils.SUBJECT_DN_PATTERN_PROPERTY, ".*ou=server.*");
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
     * Verify that {@link TrustedHeaderEvidenceIdentityProvider#canProvideIdentityFrom(Class)} can provide evidence for trusted header evidence, but not other
     * types.
     */
    @Test
    void testCanProvideIdentityFrom() {
        TrustedHeaderEvidenceIdentityProvider provider = new TrustedHeaderEvidenceIdentityProvider(mock(DatawaveUserService.class));
        assertThat(provider.canProvideIdentityFrom(TrustedHeaderEvidence.class)).isTrue();
        assertThat(provider.canProvideIdentityFrom(JWTEvidence.class)).isFalse();
        assertThat(provider.canProvideIdentityFrom(ProxiedX509CertificateEvidence.class)).isFalse();
    }

    @Test
    void testGetIdentityGivenNullEvidence() {
        TrustedHeaderEvidenceIdentityProvider provider = new TrustedHeaderEvidenceIdentityProvider(mock(DatawaveUserService.class));
        assertThatThrownBy(() -> provider.getIdentity(null)).isInstanceOf(NullPointerException.class).hasMessageContaining("Evidence may not be null");
    }

    @Test
    void testGetIdentityGivenNonJWTEvidence() {
        TrustedHeaderEvidenceIdentityProvider provider = new TrustedHeaderEvidenceIdentityProvider(mock(DatawaveUserService.class));
        JWTEvidence evidence = new JWTEvidence("token");
        assertThatThrownBy(() -> provider.getIdentity(evidence)).isInstanceOf(IllegalArgumentException.class)
                        .hasMessageContaining("Evidence type " + JWTEvidence.class.getName() + " is not supported");
    }

    /**
     * Verify that {@link JWTEvidenceIdentityProvider#getIdentity(Evidence)} will fetch users using the token.
     */
    @Test
    void testGetIdentityGivenValidEvidence() throws AuthorizationException {
        DatawaveUserService userService = mock(DatawaveUserService.class);
        TrustedHeaderEvidenceIdentityProvider provider = new TrustedHeaderEvidenceIdentityProvider(userService);

        TrustedHeaderEvidence evidence = new TrustedHeaderEvidence("subjectDn", "issuerDn", "proxiedSubjects", "proxiedIssuers");

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
}
