/**
 * Copyright (c) 2024 OpenInfra Foundation Europe and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License, Version 2.0
 * which accompanies this distribution, and is available at
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package io.github.nordix.keycloak.services.x509;

import java.security.cert.X509Certificate;

import org.jboss.resteasy.mock.MockHttpRequest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.crypto.CryptoProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.services.x509.X509ClientCertificateLookup;

import fi.protonode.certy.Credential;

/**
 * Unit tests for testing authorization of using XFCC, based on the path of the client certificate.
 */
@ExtendWith(LoggingExtension.class)
public class PathVericationTest {

    private static Credential envoy1;
    private static Credential envoy2;
    private static Credential client1;
    private static Credential client2;

    @BeforeAll
    public static void createCertificates() {
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
        client1 = new Credential().subject("CN=Client 1,OU=clients,O=example.com").ca(false).issuer(externalSubCa);
        client2 = new Credential().subject("CN=Client 2,OU=clients,O=example.com").ca(false).issuer(externalSubCa);
    }

    /**
     * Test that the client certificate chain is extracted from XFCC header when:
     * - Configuration requires client path verification.
     * - Full chain verification configured (excluding root CA).
     * - TLS level client certificate matches with the expected path.
     */
    @Test
    void testTlsRequestWithXfccFromAuthorizedProxy() throws Exception {
        X509ClientCertificateLookup lookup = Helpers.createLookupWithConfig(
                        "[[\"O=example.com,OU=clients,CN=Envoy 1\", \"CN=internal sub CA\"]]");
        X509Certificate[] tlsLayerClientCerts = Helpers.getCertificateChain(envoy1);

        HttpRequest request = new HttpRequestImpl(MockHttpRequest.create("GET", "http://foo/bar")
                        .header("x-forwarded-client-cert", Helpers.getXfccWithCert(client1)))
                                        .setClientCertificateChain(tlsLayerClientCerts);

        X509Certificate[] certs = lookup.getCertificateChain(request);

        // Check that client1 certificate from XFCC is returned.
        Assertions.assertNotNull(certs);
        Assertions.assertEquals(client1.getX509Certificate(), certs[0]);
    }

    /**
     * Test that the client certificate chain is extracted from XFCC header when:
     * - Configuration requires client path verification.
     * - Partial chain configured (only leaf-certificate given).
     * - TLS level client certificate matches with the expected path.
     */
    @Test
    void testTlsRequestWithXfccPartialChainVerification() throws Exception {
        X509ClientCertificateLookup lookup = Helpers
                .createLookupWithConfig("[[\"O=example.com,OU=clients,CN=Envoy 1\"]]");

        X509Certificate[] tlsLayerClientCerts = Helpers.getCertificateChain(envoy1);

        HttpRequest request = new HttpRequestImpl(MockHttpRequest.create("GET", "http://foo/bar")
                .header("x-forwarded-client-cert", Helpers.getXfccWithCert(client1)))
                        .setClientCertificateChain(tlsLayerClientCerts);

        // Check that client1 certificate from XFCC is returned.
        X509Certificate[] certs = lookup.getCertificateChain(request);
        Assertions.assertNotNull(certs);
        Assertions.assertEquals(client1.getX509Certificate(), certs[0]);
    }


    /**
     * Test that the client certificate chain is not extracted from XFCC header when:
     * - Configuration requires client path verification.
     * - Request has client certificate that does not match with the expected path.
     */
    @Test
    void testTlsRequestWithXfccFromUnauthorizedProxy() throws Exception {
        X509ClientCertificateLookup lookup = Helpers.createLookupWithConfig("[[\"CN=does not match\"]]");
        X509Certificate[] tlsLayerClientCerts = Helpers.getCertificateChain(envoy1);

        HttpRequest request = new HttpRequestImpl(MockHttpRequest.create("GET", "http://foo/bar")
                .header("x-forwarded-client-cert", Helpers.getXfccWithCert(client1)))
                        .setClientCertificateChain(tlsLayerClientCerts);

        // Check that no certificate is returned.
        X509Certificate[] certs = lookup.getCertificateChain(request);
        Assertions.assertNull(certs);
    }

    /**
     * Test that the client certificate chain is not extracted from XFCC header when:
     * - Request is not over TLS or client certificate was not sent.
     * - Configuration requires client path verification.
     */
    @Test
    void testNonTlsRequestWithXfcc() throws Exception {
        X509ClientCertificateLookup lookup = Helpers
                .createLookupWithConfig("[[\"O=example.com,OU=clients,CN=Envoy 1\"]]");

        HttpRequest request = new HttpRequestImpl(MockHttpRequest.create("GET", "http://foo/bar")
                .header("x-forwarded-client-cert", Helpers.getXfccWithCert(client1)));

        // Check that no certificate is returned.
        X509Certificate[] certs = lookup.getCertificateChain(request);
        Assertions.assertNull(certs);
    }

    /**
     * Test that the client certificate chain is extracted from XFCC header when:
     * - Configuration requires client path verification.
     * - Multiple allowed paths are configured.
     * - TLS level client certificate matches with one of the expected paths.
     */
    @Test
    void testTlsRequestWithXfccMultipleAllowedPaths() throws Exception {
        X509ClientCertificateLookup lookup = Helpers.createLookupWithConfig(
                "[[\"O=example.com,OU=clients,CN=Envoy 1\"],[\"O=example.com,OU=clients,CN=Envoy 2\"]]");

        X509Certificate[] tlsLayerClientCerts = Helpers.getCertificateChain(envoy1);

        HttpRequest request = new HttpRequestImpl(MockHttpRequest.create("GET", "http://foo/bar")
                .header("x-forwarded-client-cert", Helpers.getXfccWithChain(client1)))
                        .setClientCertificateChain(tlsLayerClientCerts);

        // Check that client1 certificate from XFCC is returned.
        X509Certificate[] certs = lookup.getCertificateChain(request);
        Assertions.assertNotNull(certs);
        Assertions.assertArrayEquals(client1.getCertificates(), certs);

        tlsLayerClientCerts = Helpers.getCertificateChain(envoy2);

        request = new HttpRequestImpl(MockHttpRequest.create("GET", "http://foo/bar").header("x-forwarded-client-cert",
                Helpers.getXfccWithChain(client2))).setClientCertificateChain(tlsLayerClientCerts);

        // Check that client2 certificate from XFCC is returned.
        certs = lookup.getCertificateChain(request);
        Assertions.assertNotNull(certs);
        Assertions.assertArrayEquals(client2.getCertificates(), certs);
    }

    /**
     * Test that XFCC is not processed if configured client certificate verification path is empty.
     * This can be used to disable XFCC lookup while the plugin is still enabled.
     */
    @Test
    void testTlsRequestWithXfccNoVerificationPaths() throws Exception {
        X509ClientCertificateLookup lookup = Helpers.createLookupWithConfig("[]");

        X509Certificate[] tlsLayerClientCerts = Helpers.getCertificateChain(client1);

        HttpRequest request = new HttpRequestImpl(MockHttpRequest.create("GET", "http://foo/bar")
                .header("x-forwarded-client-cert", Helpers.getXfccWithChain(client2)))
                        .setClientCertificateChain(tlsLayerClientCerts);

        // Check that client certificate from TLS layer is returned.
        X509Certificate[] certs = lookup.getCertificateChain(request);
        Assertions.assertNotNull(certs);
        Assertions.assertArrayEquals(client1.getCertificates(), certs);
    }
}
