package datawave.security.cache;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Default;
import javax.inject.Inject;

import org.apache.accumulo.core.client.AccumuloClient;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.EmptyAsset;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.security.auth.server.RealmIdentity;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.Lists;

import datawave.configuration.spring.BeanProvider;
import datawave.core.common.connection.AccumuloConnectionFactory;
import datawave.core.common.result.ConnectionPool;
import datawave.security.DnList;
import datawave.security.authorization.DatawavePrincipal;
import datawave.security.authorization.DatawaveUser;
import datawave.security.authorization.DatawaveUser.UserType;
import datawave.security.authorization.SubjectIssuerDNPair;
import datawave.security.realm.DatawaveRealmIdentityCache;
import datawave.security.system.AuthorizationCache;

@RunWith(Arquillian.class)
public class CredentialsCacheBeanTest {

    private CredentialsCacheBean ccb;

    @Inject
    private DatawaveRealmIdentityCache realmIdentityCache;

    private Cache<Principal,RealmIdentity> cache;

    @Deployment
    public static JavaArchive createDeployment() {
        System.setProperty("cdi.bean.context", "springFrameworkBeanRefContext.xml");
        // @formatter:off
        return ShrinkWrap
                .create(JavaArchive.class)
                .addPackages(true, "org.apache.deltaspike", "io.astefanutti.metrics.cdi")
                .addClasses(CredentialsCacheBean.class)
                .addAsManifestResource(EmptyAsset.INSTANCE, "beans.xml");
        // @formatter:on
    }

    @Before
    public void setUp() {
        // With Arquillian we would normally inject this bean into the test class. However there seems to be
        // an incompatibility with Arquillian and the @Singleton annotation on the bean where any method
        // invoked on the bean throws a NullPointerException. Instead, we instantiate the bean manually and
        // force CDI field injection. This gets everything loaded as we want for testing.
        // TODO: identify and resolve the underlying issue
        ccb = new CredentialsCacheBean();
        BeanProvider.injectFields(ccb);

        DatawaveUser u1 = new DatawaveUser(SubjectIssuerDNPair.of("user1", "issuer1"), UserType.USER, null, null, null, -1);
        DatawaveUser u2 = new DatawaveUser(SubjectIssuerDNPair.of("user2", "issuer2"), UserType.USER, null, null, null, -1);
        DatawaveUser s1 = new DatawaveUser(SubjectIssuerDNPair.of("server1", "issuer1"), UserType.SERVER, null, null, null, -1);

        DatawavePrincipal dp1 = new DatawavePrincipal(Arrays.asList(u1, s1));
        DatawavePrincipal dp2 = new DatawavePrincipal(Collections.singleton(u1));
        DatawavePrincipal dp3 = new DatawavePrincipal(Arrays.asList(u2, s1));

        realmIdentityCache.put(dp1, RealmIdentity.ANONYMOUS);
        realmIdentityCache.put(dp2, RealmIdentity.ANONYMOUS);
        realmIdentityCache.put(dp3, RealmIdentity.ANONYMOUS);
    }

    @After
    public void tearDown() {
        realmIdentityCache.clear();
    }

    @Test
    public void testFlushAll() {
        assertEquals(3, realmIdentityCache.getPrincipals().size());

        ccb.flushAll();

        assertEquals(0, realmIdentityCache.getPrincipals().size());
    }

    @Test
    public void testEvict() {
        Principal principal = realmIdentityCache.getPrincipals().stream().filter(p -> p.getName().startsWith("user2")).findFirst().orElse(null);
        assertNotNull(principal);
        assertEquals(3, realmIdentityCache.getPrincipals().size());
        ccb.evict("user2<issuer2>");
        assertNull(realmIdentityCache.get(principal));
        assertEquals(2, realmIdentityCache.getPrincipals().size());
    }

    @Test
    public void testListDNs() {
        ArrayList<String> expectedDns = Lists.newArrayList("user2<issuer2>", "server1<issuer1>", "user1<issuer1>");
        DnList dnList = ccb.listDNs(false);
        assertEquals(3, dnList.getDns().size());
        assertEquals(expectedDns, new ArrayList<>(dnList.getDns()));
    }

    @Test
    public void testListMatching() {
        ArrayList<String> expectedDns = Lists.newArrayList("server1<issuer1>", "user1<issuer1>");
        DnList dnList = ccb.listDNsMatching("issuer1");
        assertEquals(2, dnList.getDns().size());
        assertEquals(expectedDns, new ArrayList<>(dnList.getDns()));
    }

    @Test
    public void testList() {
        DatawaveUser u = ccb.list("user2<issuer2>");
        assertNotNull(u);
        assertEquals("user2<issuer2>", u.getName());
    }

    @Default
    @ApplicationScoped
    @AuthorizationCache
    private static class TestDatawaveRealmIdentityCache implements DatawaveRealmIdentityCache {

        private final Cache<Principal,RealmIdentity> cache = CacheBuilder.newBuilder().build();

        @Override
        public void put(Principal principal, RealmIdentity realmIdentity) {
            cache.put(principal, realmIdentity);
        }

        @Override
        public void remove(Principal principal) {
            cache.invalidate(principal);
        }

        @Override
        public RealmIdentity get(Principal principal) {
            return cache.getIfPresent(principal);
        }

        @Override
        public Set<Principal> getPrincipals() {
            return cache.asMap().keySet();
        }

        @Override
        public void clear() {
            cache.invalidateAll();
        }
    }

    private static class MockAccumuloConnectionFactory implements AccumuloConnectionFactory {
        @Override
        public AccumuloClient getClient(String userDN, Collection<String> proxiedDNs, Priority priority, Map<String,String> trackingMap) {
            return null;
        }

        @Override
        public AccumuloClient getClient(String userDN, Collection<String> proxiedDNs, String poolName, Priority priority, Map<String,String> trackingMap) {
            return null;
        }

        @Override
        public void returnClient(AccumuloClient client) {

        }

        @Override
        public String report() {
            return null;
        }

        @Override
        public List<ConnectionPool> getConnectionPools() {
            return null;
        }

        @Override
        public int getConnectionUsagePercent() {
            return 0;
        }

        @Override
        public Map<String,String> getTrackingMap(StackTraceElement[] stackTrace) {
            return null;
        }

        @Override
        public void close() throws Exception {

        }
    }
}
