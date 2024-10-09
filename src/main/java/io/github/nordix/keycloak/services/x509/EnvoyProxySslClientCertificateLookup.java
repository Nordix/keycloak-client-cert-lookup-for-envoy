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
import java.util.StringTokenizer;

import org.keycloak.http.HttpRequest;
import org.keycloak.services.x509.X509ClientCertificateLookup;

public class EnvoyProxySslClientCertificateLookup implements X509ClientCertificateLookup {

    protected final static String XFCC_HEADER = "x-forwarded-client-cert";
    protected final static String XFCC_HEADER_CERT_KEY = "Cert";
    protected final static String XFCC_HEADER_CHAIN_KEY = "Chain";

    @Override
    public void close() {
    }

    /**
     * Extracts the client certificate chain from the HTTP request forwarded by Envoy.
     *
     * The Envoy XFCC header value is a comma (“,”) separated string.
     * Each substring is an XFCC element, which holds information added by a single proxy.
     * Each XFCC element is a semicolon (“;”) separated list of key-value pairs.
     * Each key-value pair is separated by an equal sign (“=”).
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
     *
     * For Envoy documentation, see
     * https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert
     *
     * @param httpRequest The HTTP request forwarded by Envoy.
     * @return The client certificate chain extracted from the HTTP request.
     */
    @Override
    public X509Certificate[] getCertificateChain(HttpRequest httpRequest) throws GeneralSecurityException {
        String xfcc = httpRequest.getHttpHeaders().getRequestHeaders().getFirst(XFCC_HEADER);
        if (xfcc == null) {
            return null;
        }

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

        return certs;
    }

    private String decodeValue(String value) {
        // Remove enclosing quotes if present.
        if (value.startsWith("\"") && value.endsWith("\"")) {
            value = value.substring(1, value.length() - 1);
        }
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

}
