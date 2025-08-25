package datawave.security.auth;

import datawave.security.evidence.JWTEvidence;
import datawave.security.evidence.ProxiedX509PeerCertificateChainEvidence;
import datawave.security.evidence.PrunableEvidence;
import datawave.security.evidence.TrustedHeaderEvidence;
import datawave.security.util.ProxiedEntityUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.log4j.Logger;
import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.CachedIdentityAuthorizeCallback;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.auth.callback.PrincipalAuthorizeCallback;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.cache.CachedIdentity;
import org.wildfly.security.cache.IdentityCache;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.Scope;
import org.wildfly.security.mechanism.AuthenticationMechanismException;
import org.wildfly.security.mechanism._private.MechanismUtil;
import org.wildfly.security.x500.X500;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BooleanSupplier;
import java.util.function.Function;

import static datawave.security.auth.DatawaveHttpAuthenticationMechanismFactory.DATAWAVE_AUTH_NAME;
import static org.wildfly.security.mechanism._private.ElytronMessages.httpClientCert;

/**
 * A custom {@link HttpServerAuthenticationMechanism}
 */
public class DatawaveHttpAuthenticationMechanism implements HttpServerAuthenticationMechanism {
    
    public static final String PROXIED_ENTITIES_HEADER = "X-ProxiedEntitiesChain";
    public static final String PROXIED_ISSUERS_HEADER = "X-ProxiedIssuersChain";
    
    private static final Logger log = Logger.getLogger(DatawaveHttpAuthenticationMechanism.class);
    private static final String DATAWAVE_TRUSTED_HEADER_AUTHENTICATION = "dw.trusted.header.authentication";
    private static final String DATAWAVE_JWT_HEADER_AUTHENTICATION = "dw.jwt.header.authentication";
    private static final String DATAWAVE_TRUSTED_PROXIED_ENTITIES= "dw.trusted.proxied.entities";
    private static final String DATAWAVE_TRUSTED_HEADER_SUBJECT_DN = "dw.trusted.header.subjectDn";
    private static final String DATAWAVE_TRUSTED_HEADER_ISSUER_DN = "dw.trusted.header.issuerDn";
    
    private final CallbackHandler callbackHandler;
    
    private final String subjectDnHeader;
    private final String issuerDnHeader;
    private final boolean trustedHeaderAuthentication;
    private final boolean jwtHeaderAuthentication;
    private final Set<String> dnsToPrune;
    
    public DatawaveHttpAuthenticationMechanism(CallbackHandler callbackHandler) {
        this.callbackHandler = callbackHandler;
        
        this.subjectDnHeader = System.getProperty(DATAWAVE_TRUSTED_HEADER_SUBJECT_DN, "X-SSL-ClientCert-Subject".toLowerCase());
        this.issuerDnHeader = System.getProperty(DATAWAVE_TRUSTED_HEADER_ISSUER_DN, "X-SSL-ClientCert-Issuer".toLowerCase());
        this.jwtHeaderAuthentication = Boolean.parseBoolean(System.getProperty(DATAWAVE_JWT_HEADER_AUTHENTICATION, "false"));
        this.trustedHeaderAuthentication = Boolean.parseBoolean(System.getProperty(DATAWAVE_TRUSTED_HEADER_AUTHENTICATION, "false"));
        String dns = System.getProperty(DATAWAVE_TRUSTED_PROXIED_ENTITIES, null);
        if(dns != null && !dns.isBlank()) {
            this.dnsToPrune = Set.copyOf(Arrays.asList(ProxiedEntityUtils.splitProxiedDNs(dns, false)));
        } else {
            this.dnsToPrune = null;
        }
    }
    
    @Override
    public String getMechanismName() {
        return DATAWAVE_AUTH_NAME;
    }
    
    @Override
    public void evaluateRequest(HttpServerRequest request) throws HttpAuthenticationException {
        Function<SecurityDomain,IdentityCache> cacheFunction = createIdentityCacheFunction(request);
        
        if (cacheFunction != null && attemptReAuthentication(request, cacheFunction)) {
            log.trace("Re-authentication succeeded");
            return;
        }
        if(attemptAuthentication(request, cacheFunction)) {
            log.trace("Authentication succeeded");
            return;
        }
        
        log.trace("Both re-authentication and authentication failed");
        fail(request);
    }
    
    private boolean attemptReAuthentication(HttpServerRequest request, Function<SecurityDomain,IdentityCache> cacheFunction)
                    throws HttpAuthenticationException {
        CachedIdentityAuthorizeCallback authorizeCallback = new CachedIdentityAuthorizeCallback(cacheFunction, true);
        try {
            MechanismUtil.handleCallbacks(httpClientCert, callbackHandler, authorizeCallback);
        } catch (AuthenticationMechanismException e) {
            throw e.toHttpAuthenticationException();
        } catch (UnsupportedCallbackException e) {
            throw httpClientCert.mechCallbackHandlerFailedForUnknownReason(e).toHttpAuthenticationException();
        }
        boolean authorized = authorizeCallback.isAuthorized();
        if(log.isTraceEnabled()) {
            log.trace("Identity was authorized by CachedIdentityAuthorizeCallback handler: " + authorized);
        }
        if (authorized) {
            return succeed(request);
        }
        return false;
    }
    
    private boolean attemptAuthentication(HttpServerRequest request, Function<SecurityDomain,IdentityCache> cacheFunction) throws HttpAuthenticationException {
        Evidence evidence;
        try {
            evidence = getEvidence(request);
        } catch (Exception e) {
            throw new HttpAuthenticationException("Error occurred when obtaining evidence for authentication", e);
        }
        if (evidence == null) {
            request.authenticationFailed("Failed to obtain valid evidence for authentication.");
            return false;
        }
        
        if(log.isTraceEnabled()) {
            log.trace("Computed evidence: " + evidence);
        };
        
        if (dnsToPrune != null && evidence instanceof PrunableEvidence) {
            ((PrunableEvidence) evidence).pruneEntities(dnsToPrune);
            if(log.isTraceEnabled()) {
                log.trace("Computed evidence after pruning: " + evidence);
            }
        }
        
        EvidenceVerifyCallback callback = new EvidenceVerifyCallback(evidence);
        try {
            MechanismUtil.handleCallbacks(httpClientCert, callbackHandler, callback);
        } catch (UnsupportedCallbackException e) {
            throw httpClientCert.mechCallbackHandlerFailedForUnknownReason(e).toHttpAuthenticationException();
        } catch (AuthenticationMechanismException e) {
            throw e.toHttpAuthenticationException();
        }
        
        boolean verified = callback.isVerified();
        if(log.isTraceEnabled()) {
            log.trace("Evidence " + evidence.getClass().getName() + " was verified by EvidenceVerifyCallback handler. Passed verification: " + verified);
        }
        
        if (verified) {
            final BooleanSupplier authorizedFunction;
            final Callback authorizeCallBack;
            if (cacheFunction != null) {
                CachedIdentityAuthorizeCallback cacheCallback = new CachedIdentityAuthorizeCallback(evidence.getDecodedPrincipal(), cacheFunction, true);
                authorizedFunction = cacheCallback::isAuthorized;
                authorizeCallBack = cacheCallback;
            } else {
                PrincipalAuthorizeCallback principalCallback = new PrincipalAuthorizeCallback(evidence.getDecodedPrincipal());
                authorizedFunction = principalCallback::isAuthorized;
                authorizeCallBack = principalCallback;
            }
            
            try {
                MechanismUtil.handleCallbacks(httpClientCert, callbackHandler, authorizeCallBack);
            } catch (AuthenticationMechanismException e) {
                throw e.toHttpAuthenticationException();
            } catch (UnsupportedCallbackException e) {
                throw httpClientCert.mechCallbackHandlerFailedForUnknownReason(e).toHttpAuthenticationException();
            }
            
            boolean authorized = authorizedFunction.getAsBoolean();
            httpClientCert.tracef("X509PeerCertificateChainEvidence was authorized by CachedIdentityAuthorizeCallback(%s) handler: %b", evidence.getDecodedPrincipal(), authorized);
            if (authorized && succeed(request)) {
                httpClientCert.trace("Authentication succeed");
                return true;
            }
        } else {
            log.debug("Evidence authentication failed");
            request.authenticationFailed("Authentication failed");
            return false;
        }
        
        request.noAuthenticationInProgress();
        return false;
    }
    
    private boolean succeed(HttpServerRequest request) throws HttpAuthenticationException {
        try {
            MechanismUtil.handleCallbacks(httpClientCert, callbackHandler, AuthenticationCompleteCallback.SUCCEEDED);
            request.authenticationComplete();
            return true;
        } catch (AuthenticationMechanismException e) {
            throw e.toHttpAuthenticationException();
        } catch (UnsupportedCallbackException ignored) {
            // ignored
        }
        return false;
    }
    
    private void fail(HttpServerRequest request) throws HttpAuthenticationException {
        try {
            MechanismUtil.handleCallbacks(httpClientCert, callbackHandler, AuthenticationCompleteCallback.FAILED);
            request.authenticationFailed(httpClientCert.authenticationFailed());
        } catch (AuthenticationMechanismException e) {
            throw e.toHttpAuthenticationException();
        } catch (UnsupportedCallbackException ignored) {
            // ignored
        }
    }
    
    private Evidence getEvidence(HttpServerRequest request) throws MultipleHeaderException, MissingHeaderException {
        Evidence evidence = getJwtEvidence(request);
        if(evidence != null) {
            return evidence;
        }
        
        Pair<String,String> proxiedHeaderValues = getProxiedEntitiesAndIssuers(request);
        String proxiedEntities = proxiedHeaderValues.getLeft();
        String proxiedIssuers = proxiedHeaderValues.getRight();
        
        evidence = getProxiedSSLEvidence(request, proxiedEntities, proxiedIssuers);
        if(evidence != null) {
            return evidence;
        }
        
        return getTrustedHeadersEvidence(request, proxiedEntities, proxiedIssuers);
    }
    
    private Evidence getJwtEvidence(HttpServerRequest request) throws MultipleHeaderException {
        if(jwtHeaderAuthentication) {
            String authorizationHeader = getSingularHeaderValue(request, "Authorization");
            if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                String jwtToken = authorizationHeader.substring(7);
                return new JWTEvidence(jwtToken);
            }
        }
        return null;
    }
    
    private Pair<String, String> getProxiedEntitiesAndIssuers(HttpServerRequest request) throws MultipleHeaderException, MissingHeaderException {
        String proxiedEntities;
        String proxiedIssuers;
        proxiedEntities = getSingularHeaderValue(request, PROXIED_ENTITIES_HEADER);
        proxiedIssuers = getSingularHeaderValue(request, PROXIED_ISSUERS_HEADER);
        if (log.isTraceEnabled()) {
            log.trace("Authenticating with proxiedEntities=" + proxiedEntities + " and proxiedIssuers=" + proxiedIssuers);
        }
        
        // If proxied entities are specified, but proxied issuers are not, then fail authentication immediately.
        if(proxiedEntities != null && proxiedIssuers == null) {
            // todo - figure out how to fetch request start time so that we can add timing headers to response
            throw new MissingHeaderException(PROXIED_ENTITIES_HEADER + " provided, but missing " + PROXIED_ISSUERS_HEADER);
        }
        return Pair.of(proxiedEntities, proxiedIssuers);
    }
    
    private Evidence getProxiedSSLEvidence(HttpServerRequest request, String proxiedEntities, String proxiedIssuers) {
        if(request.getSSLSession() != null) {
            Certificate[] peerCertificates = request.getPeerCertificates();
            X509Certificate[] x509Certificates = X500.asX509CertificateArray(peerCertificates);
            X509Certificate certificate = x509Certificates[0];
            return new ProxiedX509PeerCertificateChainEvidence(certificate, proxiedEntities, proxiedIssuers);
        }
        return null;
    }
    
    private Evidence getTrustedHeadersEvidence(HttpServerRequest request, String proxiedEntities, String proxiedIssuers)
                    throws MultipleHeaderException, MissingHeaderException {
        if (trustedHeaderAuthentication) {
            String subjectDn = getSingularHeaderValue(request, subjectDnHeader);
            String issuerDn = getSingularHeaderValue(request, issuerDnHeader);
            if(log.isTraceEnabled()) {
                log.trace("Authenticating with trusted subject header=" + subjectDn + " and trusted issuer header=" + issuerDn);
            }
            // If no DN headers were supplied, then report no authentication happened.
            if(subjectDn == null && issuerDn == null) {
                return null;
            }
            // If either the subject DN or issuer DN is missing, report authentication failure.
            if(subjectDn == null || issuerDn == null) {
                throw new MissingHeaderException(
                                "Missing trusted subject DN (" + subjectDn + ") or issuer DN (" + issuerDn + ") for trusted header authentication");
            }
            
            return new TrustedHeaderEvidence(subjectDn, issuerDn, proxiedEntities, proxiedIssuers);
        }
        return null;
    }
    
    /**
     * Returns the value if one was provided for the given header name in the given http request. If no value was provided, null will be returned. If multiple
     * values were provided, an exception will be thrown.
     * @param httpServerRequest the http request
     * @param headerName the header name
     * @return the value, possibly null
     * @throws MultipleHeaderException if multiple values were provided for the header
     */
    private String getSingularHeaderValue(HttpServerRequest httpServerRequest, String headerName) throws MultipleHeaderException {
        List<String> values = httpServerRequest.getRequestHeaderValues(headerName);
        if(values != null && !values.isEmpty()) {
            if(values.size() > 1) {
                throw new MultipleHeaderException(headerName + " may not be specified multiple times");
            }
            return values.get(0);
        } else {
            return null;
        }
    }
    
    private Function<SecurityDomain,IdentityCache> createIdentityCacheFunction(HttpServerRequest request) {
        HttpScope scope = request.getScope(Scope.SSL_SESSION);
        return scope == null ? null : securityDomain -> new IdentityCache() {
            
            final Map<SecurityDomain,CachedIdentity> identities = MechanismUtil.computeIfAbsent(scope,
                            "org.wildfly.elytron.identity-cache", key -> new ConcurrentHashMap<>());
            
            @Override
            public void put(SecurityIdentity identity) {
                CachedIdentity cachedIdentity = new CachedIdentity(DATAWAVE_AUTH_NAME, false, identity);
                httpClientCert.tracef("storing into cache: %s", cachedIdentity);
                identities.putIfAbsent(securityDomain, cachedIdentity);
            }
            
            @Override
            public CachedIdentity get() {
                CachedIdentity cachedIdentity = identities.get(securityDomain);
                httpClientCert.tracef("loading from cache: %s", cachedIdentity);
                return cachedIdentity;
            }
            
            @Override
            public CachedIdentity remove() {
                httpClientCert.tracef("clearing identity cache");
                return identities.remove(securityDomain);
            }
        };
    }
    
    
    private static final class MultipleHeaderException extends Exception {
        private static final long serialVersionUID = 1L;
        
        public MultipleHeaderException(String message) {
            super(message);
        }
    }
    
    private static final class MissingHeaderException extends Exception {
        
        private static final long serialVersionUID = 1L;
        
        public MissingHeaderException(String message) {
            super(message);
        }
    }
}
