package datawave.security.realm;

import java.util.Map;
import java.util.Set;

import datawave.security.cert.DatawaveCertVerifier;
import datawave.security.cert.X509CertificateVerifier;
import datawave.util.StringUtils;

class DatawaveSecurityRealmConfig {

    /**
     * Whether JWT authentication is enabled.
     */
    static final String OPTION_JWT_ENABLED = "jwtEnabled";

    /**
     * Whether trusted header authentication is enabled.
     */
    static final String OPTION_TRUSTED_HEADERS_ENABLED = "trustedHeadersEnabled";

    /**
     * The fully qualified name of the certificate verifier class to use to verify the user cert during SSL authentication. Must be a class that implements 4
     * {@link X509CertificateVerifier}.
     */
    static final String OPTION_CERT_VERIFIER = "certVerifier";

    /**
     * The OSCP level to set in the certificate verifier instance if it is an instance of {@link DatawaveCertVerifier}.
     */
    static final String OPTION_OSCP_LEVEL = "oscpLevel";

    /**
     * The role that, if a user has it, should result in them being denied access.
     */
    static final String OPTION_ACCESS_DENIED_ROLE = "accessDeniedRole";

    /**
     * The roles that the terminal server in a user's proxied cert
     */
    static final String OPTION_TERMINAL_SERVER_ROLES = "terminalServerRoles";

    private static final Set<String> defaultTerminalServerRoles = Set.of(DatawaveRoles.ROLE_AUTHORIZED_SERVER, DatawaveRoles.ROLE_AUTHORIZED_QUERY_SERVER);

    private final boolean jwtEnabled;
    private final boolean trustedHeadersEnabled;
    private final String certVerifierClass;
    private final String oscpLevel;
    private final String accessDeniedRole;
    private final Set<String> terminalServerRoles;

    /**
     * Returns a new {@link DatawaveSecurityRealmConfig} initialized from the given map of configuration properties to values. Supported configuration options:
     * <ul>
     * <li>{@value OPTION_JWT_ENABLED}: A boolean that denotes whether JWT authentication is enabled for this realm. Defaults to false.</li>
     * <li>{@value OPTION_TRUSTED_HEADERS_ENABLED}: A boolean that denotes whether trusted header authentication is enabled for this realm. Defaults to false.
     * </li>
     * <li>{@value OPTION_CERT_VERIFIER}: The fully qualified class name of the {@link X509CertificateVerifier} implementation to verify user certificates with.
     * Defaults to null.</li>
     * <li>{@value OPTION_OSCP_LEVEL}: The oscp level to set in the {@link X509CertificateVerifier} if the class specified is assignable from
     * {@link DatawaveCertVerifier}. Defaults to null.</li>
     * <li>{@value OPTION_ACCESS_DENIED_ROLE}: The catch-all access denied role. If any user in a chain of users has this role, they will all be denied access.
     * Defaults to null.</li>
     * <li>{@value OPTION_TERMINAL_SERVER_ROLES}: A colon-delimited list of roles that the last proxied user in the certificate chain must, if the user is a
     * server, be assigned at least one of. Defaults to the roles {@value DatawaveRoles#ROLE_AUTHORIZED_SERVER} and
     * {@value DatawaveRoles#ROLE_AUTHORIZED_QUERY_SERVER}</li>
     * </ul>
     *
     * @param config
     *            the configuration properties
     * @return the new {@link DatawaveSecurityRealmConfig}
     */
    public static DatawaveSecurityRealmConfig fromMap(Map<String,String> config) {
        boolean jwtEnabled = Boolean.parseBoolean(config.get(OPTION_JWT_ENABLED));
        boolean trustedHeadersEnabled = Boolean.parseBoolean(config.get(OPTION_TRUSTED_HEADERS_ENABLED));
        String certVerifierClass = config.get(OPTION_CERT_VERIFIER);
        String oscpLevel = config.get(OPTION_OSCP_LEVEL);

        String accessDeniedRoleOption = config.get(OPTION_ACCESS_DENIED_ROLE);
        String accessDeniedRole = null;
        if (accessDeniedRoleOption != null) {
            accessDeniedRoleOption = accessDeniedRoleOption.trim();
            if (!accessDeniedRoleOption.isEmpty()) {
                accessDeniedRole = accessDeniedRoleOption;
            }
        }

        String terminalServerRolesOption = config.get(OPTION_TERMINAL_SERVER_ROLES);
        Set<String> terminalServerRoles = defaultTerminalServerRoles;
        if (terminalServerRolesOption != null) {
            terminalServerRoles = Set.of(StringUtils.split(terminalServerRolesOption, ':'));
        }

        return new DatawaveSecurityRealmConfig(jwtEnabled, trustedHeadersEnabled, certVerifierClass, oscpLevel, accessDeniedRole, terminalServerRoles);
    }

    public DatawaveSecurityRealmConfig(boolean jwtEnabled, boolean trustedHeadersEnabled, String certVerifierClass, String oscpLevel, String accessDeniedRole,
                    Set<String> terminalServerRoles) {
        this.jwtEnabled = jwtEnabled;
        this.trustedHeadersEnabled = trustedHeadersEnabled;
        this.certVerifierClass = certVerifierClass;
        this.oscpLevel = oscpLevel;
        this.accessDeniedRole = accessDeniedRole;
        this.terminalServerRoles = terminalServerRoles;
    }

    /**
     * Return whether JWT header authentication is enabled for the security realm.
     *
     * @return true if enabled, or false otherwise
     */
    public boolean isJwtEnabled() {
        return jwtEnabled;
    }

    /**
     * Return whether trusted header authentication is enabled for the security realm.
     *
     * @return true if enabled, or false otherwise
     */
    public boolean isTrustedHeadersEnabled() {
        return trustedHeadersEnabled;
    }

    public String getCertVerifierClass() {
        return certVerifierClass;
    }

    public String getOscpLevel() {
        return oscpLevel;
    }

    public String getAccessDeniedRole() {
        return accessDeniedRole;
    }

    public Set<String> getTerminalServerRoles() {
        return terminalServerRoles;
    }
}
