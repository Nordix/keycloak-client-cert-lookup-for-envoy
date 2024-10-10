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
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class CertificateUtils {

    static KeyStore loadTrustedCertificate(Path path)
            throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);

        X509Certificate[] certs = PemUtils.decodeCertificates(Files.readString(path));

        for (int i = 0; i < certs.length; i++) {
            keyStore.setCertificateEntry("cert-" + i, certs[i]);
        }

        return keyStore;
    }

    static KeyStore loadCredentials(Path certPath, Path keyPath, String password)
            throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {

                KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);

        X509Certificate[] certs = PemUtils.decodeCertificates(Files.readString(certPath));
        PrivateKey pkey = org.keycloak.common.util.PemUtils.decodePrivateKey(Files.readString(keyPath));

        keyStore.setKeyEntry("key", pkey, "password".toCharArray(), certs);

        return keyStore;
    }

}
