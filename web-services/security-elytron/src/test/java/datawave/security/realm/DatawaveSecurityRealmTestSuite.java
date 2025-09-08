package datawave.security.realm;

import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;

@Suite
@SelectClasses({JWTSuiteChild.class, TrustedHeaderSuiteChild.class, ProxiedX509SuiteChild.class})
public class DatawaveSecurityRealmTestSuite {}
