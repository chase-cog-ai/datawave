package datawave.security.realm;

import org.wildfly.security.authz.AuthorizationIdentity;

import datawave.security.authorization.DatawavePrincipal;

public class DatawaveAuthorizationIdentity implements AuthorizationIdentity {

    private DatawavePrincipal principal;

    public DatawavePrincipal getPrincipal() {
        return principal;
    }

    public void setPrincipal(DatawavePrincipal principal) {
        this.principal = principal;
    }
}
