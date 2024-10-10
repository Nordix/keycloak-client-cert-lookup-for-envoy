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
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.crypto.CryptoProvider;
import org.keycloak.http.HttpRequest;

public class ClientCertificateLookupTest {

    private static EnvoyProxySslClientCertificateLookup envoyLookup = null;

    @BeforeAll
    public static void setup() {
        // Initialize the Keycloak default crypto provider.
        CryptoIntegration.init(CryptoProvider.class.getClassLoader());

        envoyLookup = new EnvoyProxySslClientCertificateLookup();
    }

    @Test
    public void testCertificate() throws Exception {
        // Verify that XFCC Cert is used when only Cert is present.

        String cert = "Hash=a3d0d47ddd0db8c93ea787ef2fb025ddb64f24e6a808a55e73349486e0a890be;Cert=\"-----BEGIN%20CERTIFICATE-----%0AMIIBVTCB%2FKADAgECAggX9bbmjJbJVjAKBggqhkjOPQQDAjAYMRYwFAYDVQQDEw1j%0AbGllbnQtc3ViLWNhMB4XDTI0MDkxNjExNDUzM1oXDTI1MDkxNjExNDUzM1owFTET%0AMBEGA1UEAxMKeDUwOWNsaWVudDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJIk%0A8XcabnGpwh2tDYlrKzQ1Z2X8SNrtBo4RypOfv7Vw2dFxMqab%2F%2FnPJZafCWkO6odO%0Ao1AVYK8hv8arz2FrLtGjMzAxMA4GA1UdDwEB%2FwQEAwIFoDAfBgNVHSMEGDAWgBQk%0A4w6%2F09dXWDgQXI%2FeySP%2BJ8IruTAKBggqhkjOPQQDAgNIADBFAiEAmIsEIqyRvFWr%0A5PDbbcOK6aOVKxUkCDUE9O27ITgTURgCICl1Hju0kFnDrTNpXHABg5dmWQ%2BD6y2L%0A7LDd0viM2OVJ%0A-----END%20CERTIFICATE-----%0A\"";

        HttpRequest request = new HttpRequestImpl(
                MockHttpRequest.create("GET", "http://foo/bar").header("x-forwarded-client-cert", cert));

        X509Certificate[] certs = envoyLookup.getCertificateChain(request);
        Assertions.assertNotNull(certs);
        Assertions.assertEquals(1, certs.length);
        Assertions.assertEquals("CN=x509client", certs[0].getSubjectX500Principal().getName());
    }

    @Test
    public void testChain() throws Exception {
        // Verify that XFCC Chain is used when only Chain is present.

        String chain = "Hash=a3d0d47ddd0db8c93ea787ef2fb025ddb64f24e6a808a55e73349486e0a890be;Chain=\"-----BEGIN%20CERTIFICATE-----%0AMIIBVTCB%2FKADAgECAggX9bbmjJbJVjAKBggqhkjOPQQDAjAYMRYwFAYDVQQDEw1j%0AbGllbnQtc3ViLWNhMB4XDTI0MDkxNjExNDUzM1oXDTI1MDkxNjExNDUzM1owFTET%0AMBEGA1UEAxMKeDUwOWNsaWVudDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJIk%0A8XcabnGpwh2tDYlrKzQ1Z2X8SNrtBo4RypOfv7Vw2dFxMqab%2F%2FnPJZafCWkO6odO%0Ao1AVYK8hv8arz2FrLtGjMzAxMA4GA1UdDwEB%2FwQEAwIFoDAfBgNVHSMEGDAWgBQk%0A4w6%2F09dXWDgQXI%2FeySP%2BJ8IruTAKBggqhkjOPQQDAgNIADBFAiEAmIsEIqyRvFWr%0A5PDbbcOK6aOVKxUkCDUE9O27ITgTURgCICl1Hju0kFnDrTNpXHABg5dmWQ%2BD6y2L%0A7LDd0viM2OVJ%0A-----END%20CERTIFICATE-----%0A-----BEGIN%20CERTIFICATE-----%0AMIIBhTCCASugAwIBAgIIF%2FW25oyTeEowCgYIKoZIzj0EAwIwFDESMBAGA1UEAxMJ%0AY2xpZW50LWNhMB4XDTI0MDkxNjExNDUzM1oXDTI1MDkxNjExNDUzM1owGDEWMBQG%0AA1UEAxMNY2xpZW50LXN1Yi1jYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABG5K%0A2RWk6GVSgVlIccGNfRt3Iubpr6rz5j%2FbEpuB02G9LW3sg7x3uKfLQL4hNnpyJooR%0AhMuo%2FtPCaBFGAUCiYzqjYzBhMA4GA1UdDwEB%2FwQEAwIBBjAPBgNVHRMBAf8EBTAD%0AAQH%2FMB0GA1UdDgQWBBQk4w6%2F09dXWDgQXI%2FeySP%2BJ8IruTAfBgNVHSMEGDAWgBQZ%0Aa6PCs%2BstKIy2mwuHcKzkKtzBvjAKBggqhkjOPQQDAgNIADBFAiEA69pKJ%2FZ25TN6%0AINr8rutOQCC0Lczo23KijbTQrF4USmECIFb8RrXYV34rxmTaSWH37fqmvsYEo3mp%0AmJ5bu1L%2BL9Zo%0A-----END%20CERTIFICATE-----%0A\"";

        HttpRequest request = new HttpRequestImpl(
                MockHttpRequest.create("GET", "http://foo/bar").header("x-forwarded-client-cert", chain));
        X509Certificate[] certs = envoyLookup.getCertificateChain(request);

        Assertions.assertNotNull(certs);
        Assertions.assertEquals(2, certs.length);
        Assertions.assertEquals("CN=x509client", certs[0].getSubjectX500Principal().getName());
        Assertions.assertEquals("CN=client-sub-ca", certs[1].getSubjectX500Principal().getName());
    }


    @Test
    public void testCertificateAndChain() throws Exception {
        // Verify that XFCC Chain is used when both Cert and Chain are present.

        String certAndChain = "Hash=a3d0d47ddd0db8c93ea787ef2fb025ddb64f24e6a808a55e73349486e0a890be;Cert=\"-----BEGIN%20CERTIFICATE-----%0AMIIBVTCB%2FKADAgECAggX9bbmjJbJVjAKBggqhkjOPQQDAjAYMRYwFAYDVQQDEw1j%0AbGllbnQtc3ViLWNhMB4XDTI0MDkxNjExNDUzM1oXDTI1MDkxNjExNDUzM1owFTET%0AMBEGA1UEAxMKeDUwOWNsaWVudDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJIk%0A8XcabnGpwh2tDYlrKzQ1Z2X8SNrtBo4RypOfv7Vw2dFxMqab%2F%2FnPJZafCWkO6odO%0Ao1AVYK8hv8arz2FrLtGjMzAxMA4GA1UdDwEB%2FwQEAwIFoDAfBgNVHSMEGDAWgBQk%0A4w6%2F09dXWDgQXI%2FeySP%2BJ8IruTAKBggqhkjOPQQDAgNIADBFAiEAmIsEIqyRvFWr%0A5PDbbcOK6aOVKxUkCDUE9O27ITgTURgCICl1Hju0kFnDrTNpXHABg5dmWQ%2BD6y2L%0A7LDd0viM2OVJ%0A-----END%20CERTIFICATE-----%0A\";Chain=\"-----BEGIN%20CERTIFICATE-----%0AMIIBVTCB%2FKADAgECAggX9bbmjJbJVjAKBggqhkjOPQQDAjAYMRYwFAYDVQQDEw1j%0AbGllbnQtc3ViLWNhMB4XDTI0MDkxNjExNDUzM1oXDTI1MDkxNjExNDUzM1owFTET%0AMBEGA1UEAxMKeDUwOWNsaWVudDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJIk%0A8XcabnGpwh2tDYlrKzQ1Z2X8SNrtBo4RypOfv7Vw2dFxMqab%2F%2FnPJZafCWkO6odO%0Ao1AVYK8hv8arz2FrLtGjMzAxMA4GA1UdDwEB%2FwQEAwIFoDAfBgNVHSMEGDAWgBQk%0A4w6%2F09dXWDgQXI%2FeySP%2BJ8IruTAKBggqhkjOPQQDAgNIADBFAiEAmIsEIqyRvFWr%0A5PDbbcOK6aOVKxUkCDUE9O27ITgTURgCICl1Hju0kFnDrTNpXHABg5dmWQ%2BD6y2L%0A7LDd0viM2OVJ%0A-----END%20CERTIFICATE-----%0A-----BEGIN%20CERTIFICATE-----%0AMIIBhTCCASugAwIBAgIIF%2FW25oyTeEowCgYIKoZIzj0EAwIwFDESMBAGA1UEAxMJ%0AY2xpZW50LWNhMB4XDTI0MDkxNjExNDUzM1oXDTI1MDkxNjExNDUzM1owGDEWMBQG%0AA1UEAxMNY2xpZW50LXN1Yi1jYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABG5K%0A2RWk6GVSgVlIccGNfRt3Iubpr6rz5j%2FbEpuB02G9LW3sg7x3uKfLQL4hNnpyJooR%0AhMuo%2FtPCaBFGAUCiYzqjYzBhMA4GA1UdDwEB%2FwQEAwIBBjAPBgNVHRMBAf8EBTAD%0AAQH%2FMB0GA1UdDgQWBBQk4w6%2F09dXWDgQXI%2FeySP%2BJ8IruTAfBgNVHSMEGDAWgBQZ%0Aa6PCs%2BstKIy2mwuHcKzkKtzBvjAKBggqhkjOPQQDAgNIADBFAiEA69pKJ%2FZ25TN6%0AINr8rutOQCC0Lczo23KijbTQrF4USmECIFb8RrXYV34rxmTaSWH37fqmvsYEo3mp%0AmJ5bu1L%2BL9Zo%0A-----END%20CERTIFICATE-----%0A\"";

        HttpRequest request = new HttpRequestImpl(
                MockHttpRequest.create("GET", "http://foo/bar").header("x-forwarded-client-cert", certAndChain));
        X509Certificate[] certs = envoyLookup.getCertificateChain(request);

        Assertions.assertNotNull(certs);
        Assertions.assertEquals(2, certs.length);
        Assertions.assertEquals("CN=x509client", certs[0].getSubjectX500Principal().getName());
        Assertions.assertEquals("CN=client-sub-ca", certs[1].getSubjectX500Principal().getName());
    }


    @Test
    public void testNoCertificate() throws Exception {
        // No XFCC header.
        Assertions.assertNull(envoyLookup.getCertificateChain(new HttpRequestImpl(
                MockHttpRequest.create("GET", "http://foo/bar"))));

        // No Cert or Chain value in XFCC header.
        Assertions.assertNull(envoyLookup.getCertificateChain(new HttpRequestImpl(
            MockHttpRequest.create("GET", "http://foo/bar").header("x-forwarded-client-cert", "foobar"))));
    }

    @Test
    public void testMultipleXfccElements() throws Exception {
        // Multiple comma separated elements in XFCC header.
        String multipleElements = "Hash=a3d0d47ddd0db8c93ea787ef2fb025ddb64f24e6a808a55e73349486e0a890be;Cert=\"-----BEGIN%20CERTIFICATE-----%0AMIIBVTCB%2FKADAgECAggX9bbmjJbJVjAKBggqhkjOPQQDAjAYMRYwFAYDVQQDEw1j%0AbGllbnQtc3ViLWNhMB4XDTI0MDkxNjExNDUzM1oXDTI1MDkxNjExNDUzM1owFTET%0AMBEGA1UEAxMKeDUwOWNsaWVudDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJIk%0A8XcabnGpwh2tDYlrKzQ1Z2X8SNrtBo4RypOfv7Vw2dFxMqab%2F%2FnPJZafCWkO6odO%0Ao1AVYK8hv8arz2FrLtGjMzAxMA4GA1UdDwEB%2FwQEAwIFoDAfBgNVHSMEGDAWgBQk%0A4w6%2F09dXWDgQXI%2FeySP%2BJ8IruTAKBggqhkjOPQQDAgNIADBFAiEAmIsEIqyRvFWr%0A5PDbbcOK6aOVKxUkCDUE9O27ITgTURgCICl1Hju0kFnDrTNpXHABg5dmWQ%2BD6y2L%0A7LDd0viM2OVJ%0A-----END%20CERTIFICATE-----%0A\",Hash=a3d0d47ddd0db8c93ea787ef2fb025ddb64f24e6a808a55e73349486e0a890be;Cert=\"-----BEGIN%20CERTIFICATE-----%0AMIIBhTCCASugAwIBAgIIF%2FW25oyTeEowCgYIKoZIzj0EAwIwFDESMBAGA1UEAxMJ%0AY2xpZW50LWNhMB4XDTI0MDkxNjExNDUzM1oXDTI1MDkxNjExNDUzM1owGDEWMBQG%0AA1UEAxMNY2xpZW50LXN1Yi1jYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABG5K%0A2RWk6GVSgVlIccGNfRt3Iubpr6rz5j%2FbEpuB02G9LW3sg7x3uKfLQL4hNnpyJooR%0AhMuo%2FtPCaBFGAUCiYzqjYzBhMA4GA1UdDwEB%2FwQEAwIBBjAPBgNVHRMBAf8EBTAD%0AAQH%2FMB0GA1UdDgQWBBQk4w6%2F09dXWDgQXI%2FeySP%2BJ8IruTAfBgNVHSMEGDAWgBQZ%0Aa6PCs%2BstKIy2mwuHcKzkKtzBvjAKBggqhkjOPQQDAgNIADBFAiEA69pKJ%2FZ25TN6%0AINr8rutOQCC0Lczo23KijbTQrF4USmECIFb8RrXYV34rxmTaSWH37fqmvsYEo3mp%0AmJ5bu1L%2BL9Zo%0A-----END%20CERTIFICATE-----%0A\"";

        HttpRequest request = new HttpRequestImpl(
                MockHttpRequest.create("GET", "http://foo/bar").header("x-forwarded-client-cert", multipleElements));
        X509Certificate[] certs = envoyLookup.getCertificateChain(request);

        Assertions.assertNotNull(certs);
        Assertions.assertEquals(1, certs.length);
        Assertions.assertEquals("CN=x509client", certs[0].getSubjectX500Principal().getName());
    }

}
