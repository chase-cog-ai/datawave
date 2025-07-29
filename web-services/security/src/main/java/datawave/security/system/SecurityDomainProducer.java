package datawave.security.system;

import java.security.Principal;

import javax.annotation.Resource;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Default;
import javax.enterprise.inject.Produces;

import org.apache.log4j.Logger;
import org.jboss.security.AuthenticationManager;
import org.jboss.security.CacheableManager;


import datawave.security.SSLContextInfo;
import datawave.security.ssl.SSLContextInfoImpl;

/**
 * A producer class for generating server-security related artifacts. For one, we produce the server DN of the server that we are running inside of.
 */
@ApplicationScoped
public class SecurityDomainProducer {

    private static final Logger log = Logger.getLogger(SecurityDomainProducer.class);
    
    @Resource(name = "java:jboss/jaas/datawave")
    private AuthenticationManager authenticationManager;

    /**
     * Allow injection of an {@link SSLContextInfo} instance that is instantiated via system properties set via wildfly. This is intended to be the default way
     * to configure the instance of {@link SSLContextInfo} that should be used throughout the authentication process.
     */
    @Produces
    @Default
    public SSLContextInfo produceSSlContextInfo() throws Exception {
        SSLContextInfoImpl sslContextInfo = new SSLContextInfoImpl();
        sslContextInfo.setKeyStoreURL(System.getProperty("dw.ssl.context.info.keyStoreURL"));
        sslContextInfo.setKeyStorePassword(System.getProperty("dw.ssl.context.info.keyStorePassword"));
        sslContextInfo.setKeyStoreType(System.getProperty("dw.ssl.context.info.keyStoreType"));
        sslContextInfo.setTrustStoreURL(System.getProperty("dw.ssl.context.info.trustStoreURL"));
        sslContextInfo.setTrustStorePassword(System.getProperty("dw.ssl.context.info.trustStorePassword"));
        sslContextInfo.setTrustStoreType(System.getProperty("dw.ssl.context.info.trustStoreType"));
        sslContextInfo.reloadKeyAndTrustStore();
        return sslContextInfo;
    }

    @Produces
    @AuthorizationCache
    @SuppressWarnings("unchecked")
    public CacheableManager<Object,Principal> produceAuthManager() {
        return (authenticationManager instanceof CacheableManager) ? (CacheableManager<Object,Principal>) authenticationManager : null;
    }
}
