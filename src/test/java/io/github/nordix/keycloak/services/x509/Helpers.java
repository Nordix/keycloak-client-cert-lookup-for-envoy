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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.keycloak.Config.Scope;
import org.keycloak.services.x509.X509ClientCertificateLookup;

import fi.protonode.certy.Credential;

public class Helpers {

    static final String STORE_PASSWORD = "password";

    /**
     * Create new instance of Envoy X509 client certificate lookup implementation.
     */
    static X509ClientCertificateLookup createLookupWithConfig(String configJson) {
        Scope config = ScopeImpl.fromPairs("cert-path-verify", configJson);
        EnvoyProxySslClientCertificateLookupFactory factory = new EnvoyProxySslClientCertificateLookupFactory();
        factory.init(config);
        return factory.create(null);
    }

    static X509Certificate[] getCertificateChain(Credential cred)
            throws CertificateException, NoSuchAlgorithmException {
        return Arrays.stream(cred.getCertificates()).map(cert -> (X509Certificate) cert)
                .toArray(X509Certificate[]::new);
    }

    static String getXfccWithCert(Credential cred)
            throws CertificateException, NoSuchAlgorithmException, IOException {
        return String.format("Hash=1234;Cert=\"%s\"",
                URLEncoder.encode(cred.getCertificateAsPem(), StandardCharsets.UTF_8));
    }

    static String getXfccWithChain(Credential cred)
            throws CertificateException, NoSuchAlgorithmException, IOException {
        return String.format("Hash=1234;Chain=\"%s\"",
                URLEncoder.encode(cred.getCertificatesAsPem(), StandardCharsets.UTF_8));
    }

    static String getXfccWithCertAndChain(Credential cred)
            throws CertificateException, NoSuchAlgorithmException, IOException {
        return String.format("Hash=1234;Cert=\"%s\";Chain=\"%s\"",
                URLEncoder.encode(cred.getCertificateAsPem(), StandardCharsets.UTF_8),
                URLEncoder.encode(cred.getCertificatesAsPem(), StandardCharsets.UTF_8));
    }

    static KeyStore newKeyStore(Credential cred)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("credential", cred.getPrivateKey(), STORE_PASSWORD.toCharArray(),
                new Certificate[] { cred.getCertificate() });
        return ks;
    }

    static KeyStore newTrustStore(Credential cred)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        KeyStore ts = KeyStore.getInstance("PKCS12");
        ts.load(null, null);
        ts.setCertificateEntry("credential", cred.getCertificate());
        return ts;
    }

}
