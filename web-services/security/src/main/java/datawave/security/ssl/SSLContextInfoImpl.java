package datawave.security.ssl;

import java.io.File;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.Key;
import java.security.KeyStore;
import java.security.Provider;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.StringJoiner;

import javax.enterprise.inject.Alternative;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;

import datawave.security.SSLContextInfo;

/**
 * Default implementation of {@link SSLContextInfo} that is intended to replicate much of the original behavior in the original
 * org.jboss.security.JBossJSSESecurityDomain class provided by the legacy picketbox libraries. With the move to Wildfly Elytron, the usage of picketbox is no
 * longer needed, but there is still a need for this functionality when establishing DatawavePrincipal instances for calling clients.
 */
@Alternative
public class SSLContextInfoImpl implements SSLContextInfo {

    private KeyStore keyStore;

    private KeyManager[] keyManagers;

    private String keyStoreType = "JKS";

    private String keyStoreProvider;

    private String keyStoreProviderArgument;

    private URL keyStoreURL;

    private char[] keyStorePassword;

    private KeyStore trustStore;

    private TrustManager[] trustManagers;

    private String trustStoreType = "JKS";

    private String trustStoreProvider;

    private String trustStoreProviderArgument;

    private URL trustStoreURL;

    private char[] trustStorePassword;

    private String serverAlias;

    private String clientAlias;

    private String[] cipherSuites;

    private String[] protocols;

    private boolean clientAuth;

    /**
     * Return the keystore. Always null until {@link #reloadKeyAndTrustStore()} is called.
     *
     * @return the keystore
     */
    @Override
    public KeyStore getKeyStore() {
        return this.keyStore;
    }

    /**
     * Return the key managers. Always null until {@link #reloadKeyAndTrustStore()} is called.
     *
     * @return the keystore.
     */
    @Override
    public KeyManager[] getKeyManagers() {
        return this.keyManagers;
    }

    /**
     * Return the trust store. Always null until {@link #reloadKeyAndTrustStore()} is called.
     *
     * @return the trust store
     */
    @Override
    public KeyStore getTrustStore() {
        return this.trustStore;
    }

    /**
     * Return the trust managers. Always called until {@link #reloadKeyAndTrustStore()} is called.
     *
     * @return the trust managers
     */
    @Override
    public TrustManager[] getTrustManagers() {
        return this.trustManagers;
    }

    /**
     * Return the preferred server alias.
     *
     * @return the server alias
     */
    @Override
    public String getServerAlias() {
        return this.serverAlias;
    }

    /**
     * Set the preferred server alias.
     *
     * @param serverAlias
     *            the server alias
     */
    public void setServerAlias(String serverAlias) {
        this.serverAlias = serverAlias;
    }

    /**
     * Return the preferred client alias.
     *
     * @return the client alias
     */
    @Override
    public String getClientAlias() {
        return this.clientAlias;
    }

    /**
     * Set the preferred client alias.
     *
     * @param clientAlias
     *            the client alias
     */
    public void setClientAlias(String clientAlias) {
        this.clientAlias = clientAlias;
    }

    /**
     * Return the cipher suites.
     *
     * @return the cipher suites
     */
    @Override
    public String[] getCipherSuites() {
        return this.cipherSuites;
    }

    /**
     * Set the cipher suites.
     *
     * @param cipherSuites
     *            a comma-delimited list of cipher suites
     */
    public void setCipherSuites(String cipherSuites) {
        this.cipherSuites = cipherSuites.split(",");
    }

    /**
     * Return the protocols.
     *
     * @return the protocols
     */
    @Override
    public String[] getProtocols() {
        return this.protocols;
    }

    /**
     * Set the protocols.
     *
     * @param protocols
     *            a comma-delimited list of protocols.
     */
    public void setProtocols(String protocols) {
        this.protocols = protocols.split(",");
    }

    /**
     * Return whether the client's certificate should also be authenticated on the server side.
     *
     * @return the client auth flag
     */
    @Override
    public boolean isClientAuth() {
        return this.clientAuth;
    }

    /**
     * Set whether the client's certificate should also be authenticated on the server side.
     *
     * @param clientAuth
     *            the client auth flag
     */
    public void setClientAuth(boolean clientAuth) {
        this.clientAuth = clientAuth;
    }

    /**
     * Return the keystore type.
     *
     * @return the keystore type
     */
    public String getKeyStoreType() {
        return keyStoreType;
    }

    /**
     * Set the keystore type.
     *
     * @param keyStoreType
     *            the keystore type
     */
    public void setKeyStoreType(String keyStoreType) {
        this.keyStoreType = keyStoreType;
    }

    /**
     * Return the keystore provider class.
     *
     * @return the keystore provider
     */
    public String getKeyStoreProvider() {
        return keyStoreProvider;
    }

    /**
     * Set the keystore provider class.
     *
     * @param keyStoreProvider
     *            the keystore provider
     */
    public void setKeyStoreProvider(String keyStoreProvider) {
        this.keyStoreProvider = keyStoreProvider;
    }

    /**
     * Return the constructor arguments that should be used when initializing the keystore provider.
     *
     * @return the keystore provider arguments
     */
    public String getKeyStoreProviderArgument() {
        return keyStoreProviderArgument;
    }

    /**
     * Set the constructor arguments that should be used when initializing the keystore provider.
     *
     * @param keyStoreProviderArgument
     *            the keystore provider arguments
     */
    public void setKeyStoreProviderArgument(String keyStoreProviderArgument) {
        this.keyStoreProviderArgument = keyStoreProviderArgument;
    }

    /**
     * Return the keystore URL
     *
     * @return the keystore URL
     */
    public String getKeyStoreURL() {
        return getExternalForm(keyStoreURL);
    }

    /**
     * Set the keystore URL.
     *
     * @param keyStoreURL
     *            the keystore URL
     * @throws MalformedURLException
     *             if the url is not a valid URL, file path, or classpath resource
     */
    public void setKeyStoreURL(String keyStoreURL) throws MalformedURLException {
        this.keyStoreURL = validateKeyStoreURL(keyStoreURL);
    }

    /**
     * Return the keystore password.
     *
     * @return the keystore password
     */
    public char[] getKeyStorePassword() {
        return keyStorePassword;
    }

    /**
     * Set the keystore password.
     *
     * @param keyStorePassword
     *            the keystore password
     */
    public void setKeyStorePassword(String keyStorePassword) {
        this.keyStorePassword = keyStorePassword.toCharArray();
    }

    /**
     * Return the truststore type.
     *
     * @return the truststore type
     */
    public String getTrustStoreType() {
        return trustStoreType;
    }

    /**
     * Set the truststore type.
     *
     * @param trustStoreType
     *            the truststore type
     */
    public void setTrustStoreType(String trustStoreType) {
        this.trustStoreType = trustStoreType;
    }

    /**
     * Return the truststore provider class.
     *
     * @return the truststore provider class
     */
    public String getTrustStoreProvider() {
        return trustStoreProvider;
    }

    /**
     * Set the truststore provider class.
     *
     * @param trustStoreProvider
     *            the truststore provider class.
     */
    public void setTrustStoreProvider(String trustStoreProvider) {
        this.trustStoreProvider = trustStoreProvider;
    }

    /**
     * Return the constructor arguments that should be used when initializing the truststore provider.
     *
     * @return the keystore provider arguments
     */
    public String getTrustStoreProviderArgument() {
        return trustStoreProviderArgument;
    }

    /**
     * Set the constructor arguments that should be used when initializing the truststore provider.
     *
     * @param trustStoreProviderArgument
     *            the keystore provider arguments
     */
    public void setTrustStoreProviderArgument(String trustStoreProviderArgument) {
        this.trustStoreProviderArgument = trustStoreProviderArgument;
    }

    /**
     * Return the truststore URL
     *
     * @return the truststore URL
     */
    public String getTrustStoreURL() {
        return getExternalForm(trustStoreURL);
    }

    /**
     * Set the truststore URL.
     *
     * @param trustStoreURL
     *            the truststore URL
     * @throws MalformedURLException
     *             if the url is not a valid URL, file path, or classpath resource
     */
    public void setTrustStoreURL(String trustStoreURL) throws MalformedURLException {
        this.trustStoreURL = validateKeyStoreURL(trustStoreURL);
    }

    /**
     * Return the truststore password.
     *
     * @return the truststore password
     */
    public char[] getTrustStorePassword() {
        return trustStorePassword;
    }

    /**
     * Set the truststore password.
     *
     * @param trustStorePassword
     *            the truststore password
     */
    public void setTrustStorePassword(String trustStorePassword) {
        this.trustStorePassword = trustStorePassword.toCharArray();
    }

    /**
     * Reload the keystore and truststore. If no URL has been set for the truststore, the keystore will be used as the truststore.
     *
     * @throws Exception
     *             if an error occurs while loading the keystore and truststore.
     */
    @Override
    public void reloadKeyAndTrustStore() throws Exception {
        this.keyStore = loadKeyStore(keyStoreURL, keyStorePassword, keyStoreType, keyStoreProvider, keyStoreProviderArgument);
        this.keyManagers = loadKeyManagers();
        this.trustStore = loadKeyStore(trustStoreURL, trustStorePassword, trustStoreType, trustStoreProvider, trustStoreProviderArgument);
        if (this.trustStore == null) {
            this.trustStore = this.keyStore;
        }
        this.trustManagers = loadTrustManagers(trustStore);
    }

    /**
     * Return the key with the given alias from the keystore.
     *
     * @param alias
     *            the entry alias
     * @return the key
     * @throws Exception
     *             if the key cannot be retrieved
     */
    @Override
    public Key getKey(String alias) throws Exception {
        return keyStore.getKey(alias, keyStorePassword);
    }

    /**
     * Return the certificate with the given alias from the truststore.
     *
     * @param alias
     *            the entry alias
     * @return the certificate
     * @throws Exception
     *             if the certificate cannot be retrieved
     */
    @Override
    public Certificate getCertificate(String alias) throws Exception {
        return trustStore.getCertificate(alias);
    }

    // Return null if the given URL is null, or in its external form otherwise.
    private String getExternalForm(URL url) {
        return url == null ? null : url.toExternalForm();
    }

    // Verify that the given string is a URL, file, or classpath resource, and return it as a URL.
    private URL validateKeyStoreURL(String storeUrl) throws MalformedURLException {
        URL url = null;

        // First, try to parse it as a URL.
        try {
            url = new URL(storeUrl);
        } catch (MalformedURLException e) {
            // Not a URL or protocol without a handler.
        }

        // Next, try to locate this as a file path.
        if (url == null) {
            File file = new File(storeUrl);
            if (file.exists()) {
                url = file.toURI().toURL();
            }
        }

        // Lastly, try to locate this as a classpath resource.
        if (url == null) {
            ClassLoader loader = Thread.currentThread().getContextClassLoader();
            if (loader != null) {
                url = loader.getResource(storeUrl);
            }
        }

        // Otherwise fail.
        if (url == null) {
            throw new MalformedURLException("Failed to validate " + storeUrl + " as a URL, file, or classpath resource");
        }

        return url;
    }

    // Load and return the keystore.
    private KeyStore loadKeyStore(URL keyStoreURL, char[] keyStorePassword, String keyStoreType, String keyStoreProvider, String keyStoreProviderArgument)
                    throws Exception {
        KeyStore keyStore = null;
        if (keyStorePassword != null) {
            if (keyStoreProvider != null && keyStoreProviderArgument != null) {
                ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
                Class<?> clazz = classLoader.loadClass(keyStoreProvider);
                Class<?>[] constructorSignature = {String.class};
                Constructor<?> ctor = clazz.getConstructor(constructorSignature);
                Object[] constructorArgs = {keyStoreProviderArgument};
                Provider provider = (Provider) ctor.newInstance(constructorArgs);
                keyStore = KeyStore.getInstance(keyStoreType, provider);
            } else {
                keyStore = KeyStore.getInstance(keyStoreType);
            }

            if (!"PKCS11".equalsIgnoreCase(keyStoreType) && !"PKCS11IMPLKS".equalsIgnoreCase(keyStoreType)) {
                try (InputStream is = keyStoreURL.openStream()) {
                    keyStore.load(is, keyStorePassword);
                }
            }
        }
        return keyStore;
    }

    // Load and return the key managers.
    private KeyManager[] loadKeyManagers() throws Exception {
        String algorithm = KeyManagerFactory.getDefaultAlgorithm();
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(algorithm);
        keyManagerFactory.init(keyStore, keyStorePassword);
        KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();
        for (int i = 0; i < keyManagers.length; i++) {
            keyManagers[i] = new AliasedKeyManager((X509KeyManager) keyManagers[i], serverAlias, clientAlias);
        }
        return keyManagers;
    }

    // Load and return the trust managers.
    private TrustManager[] loadTrustManagers(KeyStore trustStore) throws Exception {
        String algorithm = TrustManagerFactory.getDefaultAlgorithm();
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(algorithm);
        trustManagerFactory.init(trustStore);
        return trustManagerFactory.getTrustManagers();
    }
}
