package datawave.security.realm;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import datawave.security.authorization.DatawavePrincipal;
import org.apache.log4j.Logger;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.authz.Roles;

import datawave.util.StringUtils;

import static datawave.security.realm.DatawaveRoles.ROLE_AUTHORIZED_PROXIED_SERVER;
import static datawave.security.realm.DatawaveRoles.ROLE_AUTHORIZED_QUERY_SERVER;
import static datawave.security.realm.DatawaveRoles.ROLE_AUTHORIZED_SERVER;
import static datawave.security.realm.DatawaveRoles.ROLE_AUTHORIZED_USER;

public class RequiredRoleDecoder implements RoleDecoder {

    private static final Logger log = Logger.getLogger(RequiredRoleDecoder.class);

    public static final String PRIMARY_USER_ROLES = "PRIMARY_USER_ROLES";
    public static final String PROXIED_USER_ROLES = "PROXIED_USER_ROLES";
    
    static final String REQUIRED_ROLES = "requiredRoles";
    
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
        if (requiredRoles == null) {
            this.requiredRoles = defaultRequiredRoles;
        } else {
            List<String> roles = Arrays.asList(StringUtils.split(requiredRoles, ","));
            this.requiredRoles = roles.isEmpty() ? Set.of() : Set.copyOf(roles);
        }
    }
    
    @Override
    public Roles decodeRoles(AuthorizationIdentity identity) {
        Attributes attributes = identity.getAttributes();
        if (attributes.containsKey(PRIMARY_USER_ROLES)) {
            Set<String> roles = new HashSet<>(Arrays.asList(StringUtils.split(PRIMARY_USER_ROLES, ":")));
            
            Set<String> proxiedRoles = new HashSet<>(Arrays.asList(StringUtils.split(PROXIED_USER_ROLES, ":")));
            if(Collections.disjoint(proxiedRoles, requiredRoles)) {
                roles.removeAll(requiredRoles);
            }
            
            return Roles.fromSet(roles);
        } else {
            return Roles.NONE;
        }
    }
}
