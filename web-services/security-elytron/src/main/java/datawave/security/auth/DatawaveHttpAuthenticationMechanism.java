package datawave.security.auth;

import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerRequest;

import javax.security.auth.callback.CallbackHandler;

/**
 * A custom {@link HttpServerAuthenticationMechanism}
 */
public class DatawaveHttpAuthenticationMechanism implements HttpServerAuthenticationMechanism {
    
    private CallbackHandler callbackHandler;
    
    public DatawaveHttpAuthenticationMechanism(CallbackHandler callbackHandler) {
        this.callbackHandler = callbackHandler;
    }
    
    @Override
    public String getMechanismName() {
        return "";
    }
    
    @Override
    public void evaluateRequest(HttpServerRequest httpServerRequest) throws HttpAuthenticationException {
    
    }
}
