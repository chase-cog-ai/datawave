package datawave.security.evidence;

import org.wildfly.security.evidence.Evidence;

import java.util.Objects;
import java.util.StringJoiner;

public class JWTEvidence implements Evidence {
    
    private final String token;
    
    public JWTEvidence(String token) {
        this.token = token;
    }
    
    public String getToken() {
        return token;
    }
    
    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        JWTEvidence that = (JWTEvidence) o;
        return Objects.equals(token, that.token);
    }
    
    @Override
    public int hashCode() {
        return Objects.hashCode(token);
    }
    
    @Override
    public String toString() {
        return new StringJoiner(", ", JWTEvidence.class.getSimpleName() + "[", "]").add("token='" + token + "'").toString();
    }
}
