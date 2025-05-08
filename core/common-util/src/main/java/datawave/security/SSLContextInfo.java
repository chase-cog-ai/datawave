package datawave.security;

import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;

/**
 * This interface replaces usages of the org.jboss.security.JSSESecurityDomain interface provided by the legacy picketbox library. A corresponding
 * implementation can be found in the datawave.security.ssl.SSLContextInfoImpl class in the datawave-ws-security module.
 */
public interface SSLContextInfo {

    default KeyStore getKeyStore() {
        return null;
    }

    default KeyManager[] getKeyManagers() {
        return new KeyManager[0];
    }

    default KeyStore getTrustStore() {
        return null;
    }

    default TrustManager[] getTrustManagers() {
        return new TrustManager[0];
    }

    default String getServerAlias() {
        return null;
    }

    default String getClientAlias() {
        return null;
    }

    default String[] getCipherSuites() {
        return new String[0];
    }

    default String[] getProtocols() {
        return new String[0];
    }

    default boolean isClientAuth() {
        return false;
    }

    default void reloadKeyAndTrustStore() throws Exception {}

    default Key getKey(String alias) throws Exception {
        return null;
    }

    default Certificate getCertificate(String alias) throws Exception {
        return null;
    }
}
