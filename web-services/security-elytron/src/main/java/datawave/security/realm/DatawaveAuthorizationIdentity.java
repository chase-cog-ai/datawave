package datawave.security.realm;

import org.wildfly.security.authz.AuthorizationIdentity;

import datawave.security.authorization.DatawavePrincipal;

import java.security.Principal;

public class DatawaveAuthorizationIdentity implements AuthorizationIdentity {

    private final DatawavePrincipal principal;
    
    public DatawaveAuthorizationIdentity(Principal principal) {
        if(principal instanceof DatawavePrincipal) {
            this.principal = (DatawavePrincipal) principal;
        } else {
            this.principal = null;
        }
    }
    
    public DatawavePrincipal getPrincipal() {
        return principal;
    }
}
