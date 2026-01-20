package datawave.security.evidence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.evidence.Evidence;

import datawave.security.authorization.DatawaveUser;
import datawave.security.authorization.JWTTokenHandler;

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
    
    /**
     * Verify that {@link JWTEvidenceIdentityProvider#getIdentity(Evidence)} throws an exception when given null evidence.
     */
    @Test
    void testGetIdentityGivenNullEvidence() {
        JWTEvidenceIdentityProvider provider = new JWTEvidenceIdentityProvider(mock(JWTTokenHandler.class));
        assertThatThrownBy(() -> provider.getIdentity(null)).isInstanceOf(NullPointerException.class).hasMessageContaining("Evidence may not be null");
    }
    
    /**
     * Verify that {@link JWTEvidenceIdentityProvider#getIdentity(Evidence)} throws an exception when given evidence that is not an instance of
     * {@link JWTEvidence}.
     */
    @Test
    void testGetIdentityGivenNonJWTEvidence() {
        JWTEvidenceIdentityProvider provider = new JWTEvidenceIdentityProvider(mock(JWTTokenHandler.class));
        Evidence otherEvidence = mock(Evidence.class);
        assertThatThrownBy(() -> provider.getIdentity(otherEvidence)).isInstanceOf(IllegalArgumentException.class)
                        .hasMessageContaining("Evidence type " + otherEvidence.getClass().getName() + " is not supported");
    }

    /**
     * Verify that {@link JWTEvidenceIdentityProvider#getIdentity(Evidence)} returns null when the JWT token handler returns a null collection of users.
     */
    @Test
    void testGetIdentityGivenNullUsersReturned() {
        JWTTokenHandler tokenHandler = mock(JWTTokenHandler.class);
        JWTEvidenceIdentityProvider provider = new JWTEvidenceIdentityProvider(tokenHandler);
        
        // Mock up the token handler behavior.
        when(tokenHandler.createUsersFromToken("token")).thenReturn(null);
        
        // Obtain the identity for the evidence.
        JWTEvidence evidence = new JWTEvidence("token");
        EvidenceIdentity identity = provider.getIdentity(evidence);
        
        // Assert the identity.
        assertThat(identity).isNull();
    }
    
    /**
     * Verify that {@link JWTEvidenceIdentityProvider#getIdentity(Evidence)} returns null when the JWT token handler returns an empty collection of users.
     */
    @Test
    void testGetIdentityGivenEmptyUsersReturned() {
        JWTTokenHandler tokenHandler = mock(JWTTokenHandler.class);
        JWTEvidenceIdentityProvider provider = new JWTEvidenceIdentityProvider(tokenHandler);
        
        // Mock up the token handler behavior.
        when(tokenHandler.createUsersFromToken("token")).thenReturn(new HashSet<>());
        
        // Obtain the identity for the evidence.
        JWTEvidence evidence = new JWTEvidence("token");
        EvidenceIdentity identity = provider.getIdentity(evidence);
        
        // Assert the identity.
        assertThat(identity).isNull();
    }
    
    /**
     * Verify that {@link JWTEvidenceIdentityProvider#getIdentity(Evidence)} returns a non-null {@link EvidenceIdentity} when the JWT token handler returns
     * a non-empty collection of users.
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
