/**
 * Copyright (c) 2024 OpenInfra Foundation Europe and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License, Version 2.0
 * which accompanies this distribution, and is available at
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package io.github.nordix.keycloak.services.x509;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

import javax.security.auth.x500.X500Principal;

import org.jboss.logging.Logger;
import org.keycloak.http.HttpRequest;
import org.keycloak.services.x509.X509ClientCertificateLookup;

/**
 * Extracts the client certificate chain from the HTTP request forwarded by Envoy.
 */
public class EnvoyProxySslClientCertificateLookup implements X509ClientCertificateLookup {

    private static Logger logger = Logger.getLogger(EnvoyProxySslClientCertificateLookup.class);

    protected final static String XFCC_HEADER = "x-forwarded-client-cert";
    protected final static String XFCC_HEADER_CERT_KEY = "Cert";
    protected final static String XFCC_HEADER_CHAIN_KEY = "Chain";

    // Each element in the list is a list of subject names expected in the client certificate chain.
    // <leaf certificate subject, intermediate certificate subject, ...>
    private List<List<X500Principal>> validCertPaths = null;

    /**
     * Constructor for creating an instance of EnvoyProxySslClientCertificateLookup.
     */
    public EnvoyProxySslClientCertificateLookup() {
    }

    /**
     * Constructor for creating an instance of EnvoyProxySslClientCertificateLookup.
     *
     * @param validCertPaths The certificate paths to validate the client certificate chain.
     */
    EnvoyProxySslClientCertificateLookup(List<List<X500Principal>> validCertPaths) {
        this.validCertPaths = validCertPaths;
    }

    @Override
    public void close() {
    }

    /**
     * Extracts the client certificate chain from the HTTP request forwarded by Envoy.
     *
     * The Envoy XFCC header value is a comma (",") separated string.
     * Each substring is an XFCC element, which holds information added by a single proxy.
     * Each XFCC element is a semicolon (";") separated list of key-value pairs.
     * Each key-value pair is separated by an equal sign ("=").
     *
     * Example:
     *
     *   x-forwarded-client-cert: key1="url encoded value 1";key2="url encoded value 2";...
     *
     * Following keys are supported by this implementation:
     *
     * 1. Cert - The entire client certificate in URL encoded PEM format.
     * 2. Chain - The entire client certificate chain (including the leaf certificate) in URL encoded PEM format.
     *
     * For Envoy documentation, see
     * https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert
     *
     * @param httpRequest The HTTP request forwarded by Envoy.
     * @return The client certificate chain extracted from the HTTP request.
     */
    @Override
    public X509Certificate[] getCertificateChain(HttpRequest httpRequest) throws GeneralSecurityException {
        // Before processing the XFCC header:
        // 1. Check if TLS level authorization is configured.
        // 2. Check if the TLS level client certificate chain matches the configured valid certificate paths.
        if (validCertPaths != null && !validCertPaths.isEmpty() && !xfccAuthorized(httpRequest)) {
            // Request is not coming from authorized client, fall back to the client certificate chain in the TLS layer.
            logger.debug("The client certificate chain does not match the configured valid certificate paths. Falling back to the TLS layer client certificate chain.");
            return httpRequest.getClientCertificateChain();
        }

        String xfcc = httpRequest.getHttpHeaders().getRequestHeaders().getFirst(XFCC_HEADER);
        if (xfcc == null) {
            return null;
        }

        logger.debugv("Received x-forwarded-client-cert: {0}", xfcc);

        // When multiple nested proxies are involved, the XFCC header may have multiple elements.
        // Extract only the first (leftmost) XFCC element, which is added by the outermost proxy that terminates the client's TLS connection.
        int comma = xfcc.indexOf(",");
        if (comma != -1) {
            xfcc = xfcc.substring(0, comma);
        }

        X509Certificate[] certs = null;

        StringTokenizer st = new StringTokenizer(xfcc, ";");
        while (st.hasMoreTokens()) {
            String token = st.nextToken();
            int index = token.indexOf("=");
            if (index != -1) {
                String key = token.substring(0, index).trim();
                String value = token.substring(index + 1).trim();

                if (key.equals(XFCC_HEADER_CHAIN_KEY)) {
                    // Chain contains the entire chain including the leaf certificate so we can stop processing the header.
                    certs = PemUtils.decodeCertificates(decodeValue(value));
                    break;
                } else if (key.equals(XFCC_HEADER_CERT_KEY)) {
                    // Cert contains only the leaf certificate. We need to continue processing the header in case Chain is present.
                    certs = PemUtils.decodeCertificates(decodeValue(value));
                }
            }
        }

        logger.debugv("Returning certificate chain with {0} certificates", certs != null ? certs.length : 0);
        if (certs != null && logger.isDebugEnabled()) {
            for (X509Certificate cert : certs) {
                logger.debugv("Subject: {0}, Issuer: {1}", cert.getSubjectX500Principal(), cert.getIssuerX500Principal());
            }
        }

        return certs;
    }

    private boolean xfccAuthorized(HttpRequest httpRequest) {
        X509Certificate[] clientChain = httpRequest.getClientCertificateChain();
        if (clientChain == null || clientChain.length == 0) {
            logger.debug("No client certificate chain found in the TLS layer.");
            return false;
        }

        return isClientCertPathValid(clientChain);
    }

    /**
     * Validates the client certificate chain against the configured valid certificate paths.
     */
    private boolean isClientCertPathValid(X509Certificate[] clientCerts) {
        if (validCertPaths.isEmpty()) {
            logger.debug("Skipping client certificate chain validation as no certificate paths are configured.");
            return true;
        }

        // Create a list of subject names from the client certificate chain.
        List<X500Principal> path = new ArrayList<>();
        for (X509Certificate cert : clientCerts) {
            path.add(cert.getSubjectX500Principal());
        }

        logger.debugv("Client certificate chain path: {0}", path);

        for (List<X500Principal> validPath : validCertPaths) {
            logger.debugv("Expected certificate path: {0}", validPath);

            // Valid path cannot be longer than the client certificate chain.
            if (path.size() < validPath.size()) {
                continue;
            }

            boolean match = true;
            for (int i = 0; i < validPath.size(); i++) {
                if (!path.get(i).equals(validPath.get(i))) {
                    match = false;
                    break;
                }
            }
            if (match) {
                logger.debug("Client certificate chain matches the expected certificate path.");
                return true;
            }

        }

        logger.debug("Client certificate chain does not match any of the expected certificate paths.");
        return false;
    }

    /**
     * Decodes the URL encoded value and removes enclosing quotes if present.
     */
    private String decodeValue(String value) {
        if (value.startsWith("\"") && value.endsWith("\"")) {
            value = value.substring(1, value.length() - 1);
        }
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

}
