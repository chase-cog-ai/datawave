package datawave.security.realm;

import datawave.security.authorization.DatawavePrincipal;
import org.wildfly.security.authz.AuthorizationIdentity;

public class DatawaveAuthorizationIdentity implements AuthorizationIdentity {
    
    private DatawavePrincipal principal;
    
    public DatawavePrincipal getPrincipal() {
        return principal;
    }
    
    public void setPrincipal(DatawavePrincipal principal) {
        this.principal = principal;
    }
}
