package datawave.security.realm;

import java.security.Principal;
import java.util.Set;

import org.wildfly.security.auth.server.RealmIdentity;

public interface DatawaveRealmIdentityCache {

    void put(Principal principal, RealmIdentity realmIdentity);

    RealmIdentity get(Principal principal);

    Set<Principal> getPrincipals();

    void clear();

    void remove(Principal principal);
}
