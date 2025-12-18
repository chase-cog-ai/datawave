package datawave.security.evidence;

import datawave.security.authorization.DatawaveUser;
import datawave.security.authorization.JWTTokenHandler;
import org.junit.jupiter.api.Test;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.evidence.Evidence;

import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JWTEvidenceIdentityProviderTest {
    
    /**
     * Verify that {@link JWTEvidenceIdentityProvider#canProvideIdentityFrom(Class)} can provide evidence for JWT evidence, but not other types.
     */
    @Test
    void testCanProvideIdentityFrom() {
        JWTEvidenceIdentityProvider provider = new JWTEvidenceIdentityProvider(mock(JWTTokenHandler.class));
        assertThat(provider.canProvideIdentityFrom(JWTEvidence.class)).isTrue();
        assertThat(provider.canProvideIdentityFrom(TrustedHeaderEvidence.class)).isFalse();
        assertThat(provider.canProvideIdentityFrom(ProxiedX509CertificateEvidence.class)).isFalse();
    }
    
    @Test
    void testGetIdentityGivenNullEvidence() {
        JWTEvidenceIdentityProvider provider = new JWTEvidenceIdentityProvider(mock(JWTTokenHandler.class));
        assertThatThrownBy(() -> provider.getIdentity(null)).isInstanceOf(NullPointerException.class).hasMessageContaining("Evidence may not be null");
    }
    
    @Test
    void testGetIdentityGivenNonJWTEvidence() {
        JWTEvidenceIdentityProvider provider = new JWTEvidenceIdentityProvider(mock(JWTTokenHandler.class));
        Evidence otherEvidence = mock(Evidence.class);
        assertThatThrownBy(() -> provider.getIdentity(otherEvidence)).isInstanceOf(IllegalArgumentException.class)
                        .hasMessageContaining("Evidence type " + otherEvidence.getClass().getName() + " is not supported");
    }
    
    /**
     * Verify that {@link JWTEvidenceIdentityProvider#getIdentity(Evidence)} will fetch users using the token.
     */
    @Test
    void testGetIdentityGivenValidEvidence() {
        JWTTokenHandler tokenHandler = mock(JWTTokenHandler.class);
        JWTEvidenceIdentityProvider provider = new JWTEvidenceIdentityProvider(tokenHandler);
        
        // Mock up the token handler behavior.
        Set<DatawaveUser> users = new HashSet<>();
        users.add(mock(DatawaveUser.class));
        when(tokenHandler.createUsersFromToken("token")).thenReturn(users);
        
        // Obtain the identity for the evidence.
        JWTEvidence evidence = new JWTEvidence("token");
        EvidenceIdentity identity = provider.getIdentity(evidence);
        
        // Assert the identity.
        assertThat(identity).isNotNull();
        assertThat(identity.getAttributes()).isEqualTo(Attributes.EMPTY);
        assertThat(identity.getUsers()).hasSize(1).containsAll(users);
    }
    
}
