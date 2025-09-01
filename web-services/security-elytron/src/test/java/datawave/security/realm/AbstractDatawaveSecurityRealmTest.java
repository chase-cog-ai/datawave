package datawave.security.realm;

import datawave.security.SSLContextInfo;
import datawave.security.authorization.DatawaveUserService;
import org.easymock.EasyMockRunner;
import org.easymock.EasyMockSupport;
import org.easymock.Mock;
import org.easymock.MockType;
import org.easymock.TestSubject;
import org.junit.runner.RunWith;

@RunWith(EasyMockRunner.class)
public abstract class AbstractDatawaveSecurityRealmTest extends EasyMockSupport {
    
    @TestSubject
    protected DatawaveSecurityRealm realm;

    @Mock(type = MockType.STRICT)
    protected SSLContextInfo sslContextInfo;

    @Mock(type = MockType.STRICT)
    protected DatawaveUserService userService;
 
    
}
