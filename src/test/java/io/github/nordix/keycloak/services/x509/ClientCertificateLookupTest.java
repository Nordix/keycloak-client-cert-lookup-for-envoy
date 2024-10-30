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
 * Unit tests for EnvoyProxySslClientCertificateLookup.
 */
@ExtendWith(LoggingExtension.class)
public class ClientCertificateLookupTest {

    private static X509ClientCertificateLookup envoyLookup = null;

    @BeforeAll
    public static void setup() {
        // Initialize the Keycloak default crypto provider.
        CryptoIntegration.init(CryptoProvider.class.getClassLoader());
        EnvoyProxySslClientCertificateLookupFactory factory = new EnvoyProxySslClientCertificateLookupFactory();
        envoyLookup = factory.create(null);
    }

    /**
     * Verify that XFCC Cert is used when Cert is present.
     */
    @Test
    void testCertificate() throws Exception {
        //
        Credential client = new Credential().subject("CN=x509client");
        String cert = Helpers.getXfccWithCert(client);

        HttpRequest request = new HttpRequestImpl(
                MockHttpRequest.create("GET", "http://foo/bar").header("x-forwarded-client-cert", cert));

        X509Certificate[] certs = envoyLookup.getCertificateChain(request);
        Assertions.assertNotNull(certs);
        Assertions.assertEquals(1, certs.length);
        Assertions.assertEquals("CN=x509client", certs[0].getSubjectX500Principal().getName());
    }

    /**
     * Verify that XFCC Chain is used when Chain is present.
     */
    @Test
    void testChain() throws Exception {
        Credential ca = new Credential().subject("CN=ca").ca(true);
        Credential subCa = new Credential().subject("CN=client-sub-ca").ca(true).issuer(ca);
        Credential client = new Credential().subject("CN=x509client").issuer(subCa);
        String chain = Helpers.getXfccWithChain(client);

        HttpRequest request = new HttpRequestImpl(
                MockHttpRequest.create("GET", "http://foo/bar").header("x-forwarded-client-cert", chain));
        X509Certificate[] certs = envoyLookup.getCertificateChain(request);

        Assertions.assertNotNull(certs);
        Assertions.assertEquals(2, certs.length);
        Assertions.assertEquals("CN=x509client", certs[0].getSubjectX500Principal().getName());
        Assertions.assertEquals("CN=client-sub-ca", certs[1].getSubjectX500Principal().getName());
    }

    /**
     * Verify that XFCC Chain is used when both Cert and Chain are present.
     */
    @Test
    void testCertificateAndChain() throws Exception {
        // Verify that XFCC Chain is used when both Cert and Chain are present.
        Credential ca = new Credential().subject("CN=ca").ca(true);
        Credential subCa = new Credential().subject("CN=client-sub-ca").ca(true).issuer(ca);
        Credential client = new Credential().subject("CN=x509client").issuer(subCa);
        String certAndChain = Helpers.getXfccWithCertAndChain(client);

        HttpRequest request = new HttpRequestImpl(
                MockHttpRequest.create("GET", "http://foo/bar").header("x-forwarded-client-cert", certAndChain));
        X509Certificate[] certs = envoyLookup.getCertificateChain(request);

        Assertions.assertNotNull(certs);
        Assertions.assertEquals(2, certs.length);
        Assertions.assertEquals("CN=x509client", certs[0].getSubjectX500Principal().getName());
        Assertions.assertEquals("CN=client-sub-ca", certs[1].getSubjectX500Principal().getName());
    }

    /**
     * No XFCC header present.
     */
    @Test
    void testNoCertificate() throws Exception {
        // No XFCC header.
        Assertions.assertNull(
                envoyLookup.getCertificateChain(new HttpRequestImpl(MockHttpRequest.create("GET", "http://foo/bar"))));

        // No Cert or Chain value in XFCC header.
        Assertions.assertNull(envoyLookup.getCertificateChain(new HttpRequestImpl(
                MockHttpRequest.create("GET", "http://foo/bar").header("x-forwarded-client-cert", "foobar"))));
    }

    /**
     * Multiple comma separated XFCC elements present.
     */
    @Test
    void testMultipleXfccElements() throws Exception {
        Credential client1 = new Credential().subject("CN=client1");
        Credential client2 = new Credential().subject("CN=client2");
        String multipleElements = Helpers.getXfccWithCert(client1) + "," + Helpers.getXfccWithCert(client2);

        HttpRequest request = new HttpRequestImpl(
                MockHttpRequest.create("GET", "http://foo/bar").header("x-forwarded-client-cert", multipleElements));
        X509Certificate[] certs = envoyLookup.getCertificateChain(request);

        Assertions.assertNotNull(certs);
        Assertions.assertEquals(1, certs.length);
        Assertions.assertEquals("CN=client1", certs[0].getSubjectX500Principal().getName());
    }

    /**
     * Corrupted certificate in XFCC header.
     */
    @Test
    void testCorruptedCertificate() throws Exception {
        HttpRequest request = new HttpRequestImpl(
                MockHttpRequest.create("GET", "http://foo/bar").header("x-forwarded-client-cert", "Cert=\"foobar\""));

        Assertions.assertThrows(SecurityException.class, () -> {
            envoyLookup.getCertificateChain(request);
        });
    }

}
