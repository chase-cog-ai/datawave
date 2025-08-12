package datawave.security.realm;

import java.security.Principal;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;

import org.wildfly.security.auth.server.RealmIdentity;

public interface DatawaveRealmIdentityCache {

    void put(Principal principal, RealmIdentity realmIdentity);

    void remove(Principal principal);

    RealmIdentity get(Principal principal);

    Set<Principal> getPrincipals();

    default RealmIdentity computeIfAbsent(Principal principal, Function<Principal,RealmIdentity> mappingFunction) {
        Objects.requireNonNull(principal, "principal cannot be null");
        Objects.requireNonNull(mappingFunction, "mappingFunction cannot be null");

        RealmIdentity identity = get(principal);
        if (identity == null) {
            RealmIdentity newIdentity = mappingFunction.apply(principal);
            if (newIdentity != null) {
                put(principal, newIdentity);
                return newIdentity;
            }
        }
        return identity;
    }

    void clear();
}
