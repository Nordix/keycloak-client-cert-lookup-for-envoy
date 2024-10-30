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
 * Envoy X509 client certificate lookup.
 *
 * Extracts the client certificate chain from the HTTP request forwarded by Envoy.
 */
public class EnvoyProxySslClientCertificateLookup implements X509ClientCertificateLookup {

    private static Logger logger = Logger.getLogger(EnvoyProxySslClientCertificateLookup.class);

    protected static final String XFCC_HEADER = "x-forwarded-client-cert";
    protected static final String XFCC_HEADER_CERT_KEY = "Cert";
    protected static final String XFCC_HEADER_CHAIN_KEY = "Chain";

    // Each element in the list is a list of subject names expected in the client certificate chain.
    // <leaf certificate subject, intermediate certificate subject, ...>
    private List<List<X500Principal>> verifyCertPaths = null;

    EnvoyProxySslClientCertificateLookup(List<List<X500Principal>> verifyCertPaths) {
        this.verifyCertPaths = verifyCertPaths;
    }

    @Override
    public void close() {
        // Intentionally left empty.
    }

    @Override
    public X509Certificate[] getCertificateChain(HttpRequest httpRequest) throws GeneralSecurityException {
        String xfcc = httpRequest.getHttpHeaders().getRequestHeaders().getFirst(XFCC_HEADER);

        // Choose between basic XFCC extraction and extraction with client cert path verification.
        if (verifyCertPaths == null) {
            return extractCertificateChainFromXfcc(xfcc);
        } else {
            return extractWithPathVerify(httpRequest, xfcc);
        }
    }

    public X509Certificate[] extractWithPathVerify(HttpRequest httpRequest, String xfcc) {
        // Get TLS layer client certificate.
        X509Certificate[] clientChainFromTls = httpRequest.getClientCertificateChain();

        // Check if the request was sent over TLS.
        if (clientChainFromTls == null || clientChainFromTls.length == 0) {
            logger.debug("No client certificate chain found in the TLS layer.");
            return null;
        }

        // No valid paths configured: fallback to TLS layer certificate (this disables XFCC lookup)
        if (verifyCertPaths.isEmpty()) {
            logger.debugv("Using client certificate from TLS layer: subject={0} chain length={1}",
                    clientChainFromTls[0].getSubjectX500Principal(),
                    clientChainFromTls.length);
            return clientChainFromTls;
        }

        // Is request coming from Envoy?
        boolean isEnvoy = checkClientCertPath(clientChainFromTls);

        // XFCC is not present.
        if (xfcc == null) {
            // 1. Request from Envoy but no XFCC header: do not return Envoy's client certificate to avoid impersonation.
            // 2. Request not from Envoy: return the client certificate chain from the TLS layer, if available.
            //    This allows clients within Envoy's perimeter to make direct requests using their own client certificate
            //    without going through Envoy.
            return isEnvoy ? null : clientChainFromTls;
        }

        // XFCC is present.

        // Request is coming from Envoy: extract the client certificate chain from the XFCC header.
        if (isEnvoy) {
            X509Certificate[] clientChainFromXfcc = extractCertificateChainFromXfcc(xfcc);
            if (clientChainFromXfcc != null && clientChainFromXfcc.length > 0) {
                logger.debugv("Using client certificate from x-forwarded-client-cert: subject={0} chain length={1}",
                        clientChainFromXfcc[0].getSubjectX500Principal(), clientChainFromXfcc.length);
            } else {
                logger.debug("No client certificate chain found in x-forwarded-client-cert header.");
            }
            return clientChainFromXfcc;
        }

        // Request is not from Envoy but XFCC is present.

        // Clients sending requests directly should never send XFCC headers: log a warning and ignore the header.
        logger.infov(
                "Ignoring x-forwarded-client-cert from client that does not match configured paths. "
                        + "subject={0}, cert-path-verify={1}",
                        clientChainFromTls[0].getSubjectX500Principal().getName(), verifyCertPaths);

        return null;
    }

    /**
     * Extracts the client certificate chain from the HTTP request forwarded by Envoy.
     *
     * The Envoy XFCC header value is a comma (",") separated string. Each substring is an XFCC element, which holds
     * information added by a single proxy. Each XFCC element is a semicolon (";") separated list of key-value pairs.
     * Each key-value pair is separated by an equal sign ("=").
     *
     * Example:
     *
     * x-forwarded-client-cert: key1="url encoded value 1";key2="url encoded value 2";...
     *
     * Following keys are supported by this implementation:
     *
     * 1. Cert - The entire client certificate in URL encoded PEM format.
     *
     * 2. Chain - The entire client certificate chain (including the leaf certificate) in URL encoded PEM format.
     *
     * For Envoy documentation, see
     * https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert
     *
     * @param httpRequest The HTTP request forwarded by Envoy.
     * @return The client certificate chain extracted from the HTTP request.
     */
    public X509Certificate[] extractCertificateChainFromXfcc(String xfcc) {
        if (xfcc == null) {
            logger.debug("No x-forwarded-client-cert header found.");
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

        try {
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
                        // Cert contains only the leaf certificate. We need to continue processing the header in case
                        // Chain is also present.
                        certs = PemUtils.decodeCertificates(decodeValue(value));
                    }
                }
            }

        } catch (Exception e) {
            logger.warnv("Failed to extract client certificate from x-forwarded-client-cert header: {0}",
                    e.getMessage());
            throw new SecurityException("Failed to extract client certificate from x-forwarded-client-cert header", e);
        }

        return certs;
    }

    /**
     * Verifies the client certificate chain against the configured expected certificate paths.
     *
     * Path is a list of subject names from the client certificate chain,
     * starting from the leaf certificate but excluding the root certificate.
     */
    private boolean checkClientCertPath(X509Certificate[] clientChain) {
        // Create a list of subject names from the client certificate chain.
        List<X500Principal> receivedPath = new ArrayList<>();
        for (X509Certificate cert : clientChain) {
            receivedPath.add(cert.getSubjectX500Principal());
        }

        logger.debugv("Client certificate path: {0}", receivedPath);

        for (List<X500Principal> expectedPath : verifyCertPaths) {
            logger.debugv("Expected certificate path: {0}", expectedPath);

            // Expected path cannot be longer than the actual client certificate chain.
            if (receivedPath.size() < expectedPath.size()) {
                continue;
            }

            boolean match = true;
            for (int i = 0; i < expectedPath.size(); i++) {
                if (!receivedPath.get(i).equals(expectedPath.get(i))) {
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
