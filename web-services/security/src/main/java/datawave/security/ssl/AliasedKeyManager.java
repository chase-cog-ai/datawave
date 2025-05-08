package datawave.security.ssl;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;

public class AliasedKeyManager extends X509ExtendedKeyManager {

    private final X509KeyManager delegate;
    private final String serverAlias;
    private final String clientAlias;

    public AliasedKeyManager(X509KeyManager keyManager, String serverAlias, String clientAlias) {
        this.delegate = keyManager;
        this.serverAlias = serverAlias;
        this.clientAlias = clientAlias;
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] principals) {
        return delegate.getClientAliases(keyType, principals);
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] principals, Socket socket) {
        return clientAlias != null ? clientAlias : delegate.chooseClientAlias(keyType, principals, socket);
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] principals) {
        return delegate.getServerAliases(keyType, principals);
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] principals, Socket socket) {
        return serverAlias != null ? serverAlias : delegate.chooseServerAlias(keyType, principals, socket);
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        return delegate.getCertificateChain(alias);
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        return delegate.getPrivateKey(alias);
    }

    @Override
    public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
        // @formatter:off
        return delegate instanceof X509ExtendedKeyManager ?
                        ((X509ExtendedKeyManager) delegate).chooseEngineClientAlias(keyType, issuers, engine) :
                        super.chooseEngineClientAlias(keyType, issuers, engine);
        // @formatter:on
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        // @formatter:off
        return delegate instanceof X509ExtendedKeyManager ?
                        ((X509ExtendedKeyManager)delegate).chooseEngineServerAlias(keyType, issuers, engine) :
                        super.chooseEngineServerAlias(keyType, issuers, engine);
        // @formatter:on
    }
}
