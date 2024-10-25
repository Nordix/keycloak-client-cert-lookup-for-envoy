/**
 * Copyright (c) 2024 OpenInfra Foundation Europe and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License, Version 2.0
 * which accompanies this distribution, and is available at
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package io.github.nordix.keycloak.services.x509;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.jboss.resteasy.mock.MockHttpRequest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.Config.Scope;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.crypto.CryptoProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.services.x509.X509ClientCertificateLookup;

import fi.protonode.certy.Credential;

public class PathValidationTest {

    private static Credential envoy1;
    private static Credential envoy2;
    private static Credential client1;
    private static Credential client2;

    @BeforeAll
    public static void createCertificates() throws Exception {
        // Initialize the Keycloak default crypto provider.
        CryptoIntegration.init(CryptoProvider.class.getClassLoader());

        // Certs used for Envoy->Keycloak the perimeter of the Envoy proxy, e.g.
        // Kubernetes cluster-internal PKI.
        Credential internalRootCa = new Credential().subject("CN=internal root CA");
        Credential internalSubCa = new Credential().subject("CN=internal sub CA").ca(true).issuer(internalRootCa);
        envoy1 = new Credential().subject("CN=Envoy 1,OU=clients,O=example.com").ca(false).issuer(internalSubCa);
        envoy2 = new Credential().subject("CN=Envoy 2,OU=clients,O=example.com").ca(false).issuer(internalSubCa);

        // Following certificfates represent the PKI for external clients.
        Credential externalRootCa = new Credential().subject("CN=external root CA");
        Credential externalSubCa = new Credential().subject("CN=external sub CA").ca(true).issuer(externalRootCa);
        client1 = new Credential().subject("CN=Client 1,OU=clients,O=example.com").ca(false)
                .issuer(externalSubCa);
        client2 = new Credential().subject("CN=Client 2,OU=clients,O=example.com").ca(false)
                .issuer(externalSubCa);
    }

    /**
     * Test that the client certificate chain is extracted from XFCC header when
     * request is over TLS and client certificate matches with the expected path.
     */
    @Test
    public void testTlsRequestWithXfccFromAuthorizedProxy() throws Exception {
        X509ClientCertificateLookup lookup = createLookupWithConfig("[[\"O=example.com,OU=clients,CN=Envoy 1\"]]");
        X509Certificate[] tlsLayerClientCerts = getCertificateChain(envoy1);

        HttpRequest request = new HttpRequestImpl(
                MockHttpRequest.create("GET", "http://foo/bar").header("x-forwarded-client-cert",
                        getXfccValue(client1)))
                .setClientCertificateChain(tlsLayerClientCerts);

        X509Certificate[] certs = lookup.getCertificateChain(request);

        // Check that client1 certificate from XFCC is returned.
        Assertions.assertNotNull(certs);
        Assertions.assertEquals(2, certs.length);
        Assertions.assertArrayEquals(client1.getCertificates(), certs);
    }

    /**
     * Test that the client certificate chain is not extracted from XFCC header when
     * request is over TLS and client certificate does not match with the expected
     * path.
     */
    @Test
    public void testTlsRequestWithXfccFromUnauthorizedProxy() throws Exception {
        X509ClientCertificateLookup lookup = createLookupWithConfig("[[\"CN=does not match\"]]");
        X509Certificate[] tlsLayerClientCerts = getCertificateChain(envoy1);

        HttpRequest request = new HttpRequestImpl(
                MockHttpRequest.create("GET", "http://foo/bar").header("x-forwarded-client-cert",
                        getXfccValue(client1)))
                .setClientCertificateChain(tlsLayerClientCerts);

        // Check that envoy1 certificate is returned.
        X509Certificate[] certs = lookup.getCertificateChain(request);
        Assertions.assertNotNull(certs);
        Assertions.assertEquals(2, certs.length);
        Assertions.assertArrayEquals(envoy1.getCertificates(), certs);
    }

    /**
     * Test that the client certificate chain is not extracted from XFCC header when
     * the request is not over TLS and the configuration requires certificate path
     * validation.
     */
    @Test
    public void testNonTlsRequestWithXfcc() throws Exception {
        X509ClientCertificateLookup lookup = createLookupWithConfig("[[\"O=example.com,OU=clients,CN=Envoy 1\"]]");

        HttpRequest request = new HttpRequestImpl(
                MockHttpRequest.create("GET", "http://foo/bar").header("x-forwarded-client-cert",
                        getXfccValue(client1)));

        // Check that no certificate is returned.
        X509Certificate[] certs = lookup.getCertificateChain(request);
        Assertions.assertNull(certs);
    }

    /**
     * Test that the client certificate chain is extracted from XFCC header when
     * request is over TLS and client certificate matches with one of multiple
     * expected paths.
     */
    @Test
    public void testTlsRequestWithXfccMultipleAllowedProxies() throws Exception {
        X509ClientCertificateLookup lookup = createLookupWithConfig(
                "[[\"O=example.com,OU=clients,CN=Envoy 1\"],[\"O=example.com,OU=clients,CN=Envoy 2\"]]");

        X509Certificate[] tlsLayerClientCerts = getCertificateChain(envoy1);

        HttpRequest request = new HttpRequestImpl(
                MockHttpRequest.create("GET", "http://foo/bar").header("x-forwarded-client-cert",
                        getXfccValue(client1)))
                .setClientCertificateChain(tlsLayerClientCerts);

        // Check that client1 certificate from XFCC is returned.
        X509Certificate[] certs = lookup.getCertificateChain(request);
        Assertions.assertNotNull(certs);
        Assertions.assertEquals(2, certs.length);
        Assertions.assertArrayEquals(client1.getCertificates(), certs);

        tlsLayerClientCerts = getCertificateChain(envoy2);

        request = new HttpRequestImpl(
                MockHttpRequest.create("GET", "http://foo/bar").header("x-forwarded-client-cert",
                        getXfccValue(client2)))
                .setClientCertificateChain(tlsLayerClientCerts);

        // Check that client2 certificate from XFCC is returned.
        certs = lookup.getCertificateChain(request);
        Assertions.assertNotNull(certs);
        Assertions.assertEquals(2, certs.length);
        Assertions.assertArrayEquals(client2.getCertificates(), certs);
    }


    // Helper methods.

    private static X509ClientCertificateLookup createLookupWithConfig(String configJson) {
        Scope config = ScopeImpl.fromPairs("cert-path-verify", configJson);
        EnvoyProxySslClientCertificateLookupFactory factory = new EnvoyProxySslClientCertificateLookupFactory();
        factory.init(config);
        return factory.create(null);
    }

    private static X509Certificate[] getCertificateChain(Credential cred)
            throws CertificateException, NoSuchAlgorithmException {
        return Arrays.stream(cred.getCertificates()).map(cert -> (X509Certificate) cert)
                .toArray(X509Certificate[]::new);
    }

    private static String getXfccValue(Credential cred)
            throws CertificateException, NoSuchAlgorithmException, IOException {
        return String.format("Hash=1234;Cert=\"%s\"",
                URLEncoder.encode(cred.getCertificatesAsPem(), StandardCharsets.UTF_8));
    }
}
