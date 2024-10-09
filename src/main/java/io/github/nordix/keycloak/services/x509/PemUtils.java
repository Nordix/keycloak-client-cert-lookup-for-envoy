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
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class PemUtils {

    public static final String END_CERT = "-----END CERTIFICATE-----";

    /**
     * Decode one or more X509 Certificates from a PEM string (certificate bundle).
     *
     * @param certs
     * @return the list of X509 Certificates
     * @throws Exception
     */
    public static X509Certificate[] decodeCertificates(String certs) {
        String[] pemBlocks = certs.split(END_CERT);

        List<X509Certificate> x509Certificates = Arrays.stream(pemBlocks)
                .filter(pemBlock -> pemBlock != null && !pemBlock.trim().isEmpty())
                .map(pemBlock -> org.keycloak.common.util.PemUtils.decodeCertificate(pemBlock + END_CERT))
                .collect(Collectors.toList());

        return x509Certificates.toArray(new X509Certificate[x509Certificates.size()]);
    }
}
