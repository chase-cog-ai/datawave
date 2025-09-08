package datawave.security.realm;

import static datawave.security.realm.DatawaveRoles.ROLE_AUTHORIZED_PROXIED_SERVER;
import static datawave.security.realm.DatawaveRoles.ROLE_AUTHORIZED_QUERY_SERVER;
import static datawave.security.realm.DatawaveRoles.ROLE_AUTHORIZED_SERVER;
import static datawave.security.realm.DatawaveRoles.ROLE_AUTHORIZED_USER;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.Logger;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.authz.Roles;

import datawave.util.StringUtils;

public class RequiredRoleDecoder implements RoleDecoder {

    private static final Logger log = Logger.getLogger(RequiredRoleDecoder.class);

    public static final String PRIMARY_USER_ROLES = "PRIMARY_USER_ROLES";
    public static final String PROXIED_USER_ROLES = "PROXIED_USER_ROLES";

    static final String OPTION_REQUIRED_ROLES = "requiredRoles";

    // @formatter:off
    private static final Set<String> defaultRequiredRoles = Set.of(
                    ROLE_AUTHORIZED_USER,
                    ROLE_AUTHORIZED_SERVER,
                    ROLE_AUTHORIZED_QUERY_SERVER,
                    ROLE_AUTHORIZED_PROXIED_SERVER);
    // @formatter:on

    private Set<String> requiredRoles = Set.of();

    /**
     * Initializes this security realm with the given configuration options.
     *
     * @param config
     *            the configuration
     */
    public void initialize(Map<String,String> config) {
        if (log.isTraceEnabled()) {
            log.trace("Initializing " + RequiredRoleDecoder.class.getName() + " with config=" + config);
        }

        initRequiredRoles(config.get(OPTION_REQUIRED_ROLES));

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
        if (requiredRoles == null) {
            if (log.isTraceEnabled()) {
                log.trace("No required roles specified, using default roles " + defaultRequiredRoles);
            }
            this.requiredRoles = defaultRequiredRoles;
        } else {
            List<String> roles = Arrays.asList(StringUtils.split(requiredRoles, ":"));
            this.requiredRoles = roles.isEmpty() ? Set.of() : Set.copyOf(roles);
            if (log.isTraceEnabled()) {
                log.trace("Using required roles " + requiredRoles);
            }
        }
    }

    @Override
    public Roles decodeRoles(AuthorizationIdentity identity) {
        Attributes attributes = identity.getAttributes();
        if (attributes.containsKey(PRIMARY_USER_ROLES)) {
            // Fetch the set of roles that the user is assigned.
            Set<String> roles = new HashSet<>(attributes.get(PRIMARY_USER_ROLES));

            // Fetch all roles found for proxied users.
            Set<String> proxiedRoles = new HashSet<>(attributes.get(PROXIED_USER_ROLES));
            // If any of the required roles are not found for the proxied users, remove them from the final set of roles.
            if (Collections.disjoint(proxiedRoles, requiredRoles)) {
                roles.removeAll(requiredRoles);
            }

            // Return the set of roles for the user.
            return Roles.fromSet(roles);
        } else {
            return Roles.NONE;
        }
    }
}
