package datawave.security.ssl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.Key;
import java.security.cert.Certificate;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class SSLContextInfoImplTest {

    private static final String JKS = "JKS";
    private static final String PKCS12 = "PKCS12";

    private static final String jksKeyStorePath = "/datawave-server-keystore.jks";
    private static final String jksTrustStorePath = "/datawave-server-truststore.jks";
    private static final String pkcs12KeyStorePath = "/datawave-server-keystore.p12";
    private static final String pkcs12TrustStorePath = "/datawave-server-truststore.p12";

    private static final String password = "ChangeIt";

    @Test
    void testJKSKeyStore() throws Exception {
        SSLContextInfoImpl sslContext = new SSLContextInfoImpl();
        sslContext.setKeyStoreType(JKS);
        sslContext.setKeyStorePassword(password);
        sslContext.setKeyStoreURL(getResource(jksKeyStorePath));

        sslContext.reloadKeyAndTrustStore();

        assertNotNull(sslContext.getKeyStore(), "Keystore is null");
        assertNotNull(sslContext.getTrustStore(), "Truststore is null");
        assertSame(sslContext.getKeyStore(), sslContext.getTrustStore(), "Keystore and truststore are not the same instance");
    }

    @Test
    void testJKSKeyStoreWithPKCS12TrustStore() throws Exception {
        SSLContextInfoImpl sslContext = new SSLContextInfoImpl();
        sslContext.setKeyStoreType(JKS);
        sslContext.setKeyStorePassword(password);
        sslContext.setKeyStoreURL(getResource(jksKeyStorePath));
        sslContext.setTrustStoreType(PKCS12);
        sslContext.setTrustStorePassword(password);
        sslContext.setTrustStoreURL(getResource(pkcs12TrustStorePath));

        sslContext.reloadKeyAndTrustStore();

        assertNotNull(sslContext.getKeyStore(), "Keystore is null");
        assertEquals(JKS, sslContext.getKeyStore().getType(), "Keystore is incorrect type");
        assertNotNull(sslContext.getTrustStore(), "Truststore is null");
        assertEquals(PKCS12, sslContext.getTrustStore().getType(), "Truststore is incorrect type");
        assertNotSame(sslContext.getKeyStore(), sslContext.getTrustStore(), "Keystore and truststore are the same instance");
    }

    @Test
    void testPKCS12KeyStore() throws Exception {
        SSLContextInfoImpl sslContext = new SSLContextInfoImpl();
        sslContext.setKeyStoreType(PKCS12);
        sslContext.setKeyStorePassword(password);
        sslContext.setKeyStoreURL(getResource(pkcs12KeyStorePath));

        sslContext.reloadKeyAndTrustStore();

        assertNotNull(sslContext.getKeyStore(), "Keystore is null");
        assertNotNull(sslContext.getTrustStore(), "Truststore is null");
        assertSame(sslContext.getKeyStore(), sslContext.getTrustStore(), "Keystore and truststore are not the same instance");
    }

    @Test
    void testPKCS12KeyStoreWithJKSTrustStore() throws Exception {
        SSLContextInfoImpl sslContext = new SSLContextInfoImpl();
        sslContext.setKeyStoreType(PKCS12);
        sslContext.setKeyStorePassword(password);
        sslContext.setKeyStoreURL(getResource(pkcs12KeyStorePath));
        sslContext.setTrustStoreType(JKS);
        sslContext.setTrustStorePassword(password);
        sslContext.setTrustStoreURL(getResource(jksTrustStorePath));

        sslContext.reloadKeyAndTrustStore();

        assertNotNull(sslContext.getKeyStore(), "Keystore is null");
        assertEquals(PKCS12, sslContext.getKeyStore().getType(), "Keystore is incorrect type");
        assertNotNull(sslContext.getTrustStore(), "Truststore is null");
        assertEquals(JKS, sslContext.getTrustStore().getType(), "Truststore is incorrect type");
        assertNotSame(sslContext.getKeyStore(), sslContext.getTrustStore(), "Keystore and truststore are the same instance");
    }

    @Test
    void testParsingCipherSuites() {
        SSLContextInfoImpl sslContext = new SSLContextInfoImpl();
        sslContext.setCipherSuites("AES,DES,RSA");
        assertArrayEquals(new String[] {"AES", "DES", "RSA"}, sslContext.getCipherSuites());
    }

    @Test
    void testParsingProtocols() {
        SSLContextInfoImpl sslContext = new SSLContextInfoImpl();
        sslContext.setProtocols("TLSv1.1,TLSv1.2");
        assertArrayEquals(new String[] {"TLSv1.1", "TLSv1.2"}, sslContext.getProtocols());
    }

    @Test
    void testGetKey() throws Exception {
        SSLContextInfoImpl sslContext = new SSLContextInfoImpl();
        sslContext.setKeyStoreType(JKS);
        sslContext.setKeyStorePassword(password);
        sslContext.setKeyStoreURL(getResource(jksKeyStorePath));
        sslContext.setTrustStoreType(PKCS12);
        sslContext.setTrustStorePassword(password);
        sslContext.setTrustStoreURL(getResource(pkcs12TrustStorePath));

        sslContext.reloadKeyAndTrustStore();

        Key key = sslContext.getKey("datawave-server");
        assertNotNull(key, "Key is null");

        key = sslContext.getKey("nonexistent");
        Assertions.assertNull(key, "Key is not null");
    }

    @Test
    void testGetCertificate() throws Exception {
        SSLContextInfoImpl sslContext = new SSLContextInfoImpl();
        sslContext.setKeyStoreType(JKS);
        sslContext.setKeyStorePassword(password);
        sslContext.setKeyStoreURL(getResource(jksKeyStorePath));
        sslContext.setTrustStoreType(PKCS12);
        sslContext.setTrustStorePassword(password);
        sslContext.setTrustStoreURL(getResource(pkcs12TrustStorePath));

        sslContext.reloadKeyAndTrustStore();

        Certificate certificate = sslContext.getCertificate("datawave-ca");
        assertNotNull(certificate, "Certificate is null");

        certificate = sslContext.getCertificate("nonexistent");
        Assertions.assertNull(certificate, "Certificate is not null");
    }

    @Test
    void testSetKeyStoreURLGivenURL() throws MalformedURLException {
        String keystoreURL = getResource(jksKeyStorePath);

        SSLContextInfoImpl sslContext = new SSLContextInfoImpl();
        sslContext.setKeyStoreURL(keystoreURL);

        assertEquals(keystoreURL, sslContext.getKeyStoreURL(), "Keystore URL is incorrect");
    }

    @Test
    void testSetKeyStoreURLGivenFilePath() throws MalformedURLException {
        String keystoreUrl = getResource(jksKeyStorePath);
        String keystorePath = keystoreUrl.replaceAll("file:", "");

        SSLContextInfoImpl sslContext = new SSLContextInfoImpl();
        sslContext.setKeyStoreURL(keystorePath);

        assertEquals(keystoreUrl, sslContext.getKeyStoreURL(), "Keystore URL is incorrect");
    }

    @Test
    void testInvalidKeystoreUrl() {
        SSLContextInfoImpl sslContext = new SSLContextInfoImpl();
        Assertions.assertThrows(MalformedURLException.class, () -> sslContext.setKeyStoreURL("bad_url"),
                        "Failed to validate bad_url as a URL, file, or classpath resource");
    }

    @Test
    void testSetTrustStoreURLGivenURL() throws MalformedURLException {
        String trustStoreUrl = getResource(jksTrustStorePath);

        SSLContextInfoImpl sslContext = new SSLContextInfoImpl();
        sslContext.setTrustStoreURL(trustStoreUrl);

        assertEquals(trustStoreUrl, sslContext.getTrustStoreURL(), "Truststore URL is incorrect");
    }

    @Test
    void testSetTrustStoreURLGivenFilePath() throws MalformedURLException {
        String trustStoreUrl = getResource(jksTrustStorePath);
        String trustStorePath = trustStoreUrl.replaceAll("file:", "");

        SSLContextInfoImpl sslContext = new SSLContextInfoImpl();
        sslContext.setTrustStoreURL(trustStorePath);

        assertEquals(trustStoreUrl, sslContext.getTrustStoreURL(), "Truststore URL is incorrect");
    }

    @Test
    void testInvalidTrustStoreUrl() {
        SSLContextInfoImpl sslContext = new SSLContextInfoImpl();
        Assertions.assertThrows(MalformedURLException.class, () -> sslContext.setTrustStoreURL("bad_url"),
                        "Failed to validate bad_url as a URL, file, or classpath resource");
    }

    private String getResource(String resource) {
        URL url = getClass().getResource(resource);
        if (url != null) {
            return url.toExternalForm();
        } else {
            throw new NullPointerException("Could not load resource " + resource);
        }
    }
}
