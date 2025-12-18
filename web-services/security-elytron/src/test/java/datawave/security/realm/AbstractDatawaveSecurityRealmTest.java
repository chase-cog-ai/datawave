package datawave.security.realm;

import datawave.security.SSLContextInfo;
import datawave.security.authorization.DatawaveUserService;

public abstract class AbstractDatawaveSecurityRealmTest {

    protected DatawaveSecurityRealm realm;

    protected SSLContextInfo sslContextInfo;

    protected DatawaveUserService userService;

}
