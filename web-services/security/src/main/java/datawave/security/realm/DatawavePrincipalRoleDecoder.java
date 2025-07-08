package datawave.security.realm;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.Logger;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.authz.Roles;

import datawave.security.authorization.DatawavePrincipal;
import datawave.util.StringUtils;

public class DatawavePrincipalRoleDecoder implements RoleDecoder {

    private static final Logger log = Logger.getLogger(DatawavePrincipalRoleDecoder.class);

    static final String ROLE_AUTHORIZED_USER = "AuthorizedUser";
    static final String ROLE_AUTHORIZED_SERVER = "AuthorizedServer";
    static final String ROLE_AUTHORIZED_QUERY_SERVER = "AuthorizedQueryServer";
    static final String ROLE_AUTHORIZED_PROXIED_SERVER = "AuthorizedProxiedServer";

    static final String REQUIRED_ROLES = "requiredRoles";

    private static final Set<String> defaultRequiredRoles = Set.of(ROLE_AUTHORIZED_USER, ROLE_AUTHORIZED_SERVER, ROLE_AUTHORIZED_QUERY_SERVER,
                    ROLE_AUTHORIZED_PROXIED_SERVER);

    private final Set<String> requiredRoles = new HashSet<>();

    /**
     * Initializes this security realm with the given configuration options.
     *
     * @param config
     *            the configuration
     */
    public void initialize(Map<String,String> config) {
        if (log.isTraceEnabled()) {
            log.trace("enter: initialize(Map): config=" + config);
        }

        initRequiredRoles(config.get(REQUIRED_ROLES));

        if (log.isTraceEnabled()) {
            log.trace("exit: initialize(Map)");
        }
    }

    /**
     * Initialize the required roles for this decoder from a colon-delimited list of roles. If the given string is not null, the roles will be cleared, and the
     * new roles added. Otherwise, all default required roles will be added.
     *
     * @param requiredRoles
     *            the required roles
     */
    private void initRequiredRoles(String requiredRoles) {
        if (requiredRoles != null) {
            this.requiredRoles.clear();
            this.requiredRoles.addAll(Arrays.asList(StringUtils.split(requiredRoles, ':', false)));
        } else {
            this.requiredRoles.addAll(defaultRequiredRoles);
        }
    }

    @Override
    public Roles decodeRoles(AuthorizationIdentity authorizationIdentity) {
        if (authorizationIdentity instanceof DatawaveAuthorizationIdentity) {
            DatawaveAuthorizationIdentity identity = (DatawaveAuthorizationIdentity) authorizationIdentity;
            DatawavePrincipal principal = identity.getPrincipal();
            return decodeRoles(principal);
        } else {
            log.warn("Authorization identity does not implement DatawaveAuthorizationIdentity");
            return Roles.NONE;
        }
    }

    private Roles decodeRoles(DatawavePrincipal principal) {
        try {
            Set<String> roles = new HashSet<>();
            Collection<String> primaryUserRoles = principal.getPrimaryUser().getRoles();
            if (primaryUserRoles != null) {
                roles.addAll(primaryUserRoles);

                if (principal.getProxiedUsers().stream().anyMatch(u -> Collections.disjoint(u.getRoles(), requiredRoles))) {
                    roles.removeAll(requiredRoles);
                }
            }

            log.debug("[" + roles.size() + "] Roles for " + principal.getName() + "{" + String.join(":", roles) + "}");
            return Roles.fromSet(roles);
        } catch (RuntimeException e) {
            log.warn("Error while decoding roles for datawave principal " + principal, e);
            return Roles.NONE;
        }
    }
}
