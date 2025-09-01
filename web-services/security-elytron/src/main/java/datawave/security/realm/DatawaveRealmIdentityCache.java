package datawave.security.realm;

import datawave.security.authorization.DatawavePrincipal;
import org.wildfly.security.auth.server.RealmIdentity;

import java.security.Principal;
import java.util.Set;

public interface DatawaveRealmIdentityCache {
    
    void put(Principal principal, RealmIdentity realmIdentity);
    
    RealmIdentity get(Principal principal);
    
    Set<Principal> getPrincipals();
    
    void clear();
    
    void remove(Principal principal);
}
