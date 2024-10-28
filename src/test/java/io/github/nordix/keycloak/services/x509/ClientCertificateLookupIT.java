/**
 * Copyright (c) 2024 OpenInfra Foundation Europe and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License, Version 2.0
 * which accompanies this distribution, and is available at
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package io.github.nordix.keycloak.services.x509;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;

import org.jboss.logging.Logger;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.crypto.CryptoProvider;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import fi.protonode.certy.Credential;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.Form;
import jakarta.ws.rs.core.Response;

/**
 * Integration tests with Envoy and Keycloak.
 */
public class ClientCertificateLookupIT {

    private static final String BASE_URL = "https://keycloak-https.127.0.0.1.nip.io:8443";

    private static Logger logger = Logger.getLogger(ClientCertificateLookupIT.class);

    private static String baseDir = System.getProperty("user.dir");
    private static Path targetDir = Paths.get(baseDir, "target/certs");

    private static KeyStore serverCaStore;
    private static KeyStore trustedClientStore;
    private static KeyStore untrustedClientStore;

    private static Form form = new Form()
            .param("client_id", "xfcc-client")
            .param("grant_type", "client_credentials");

    static {
        try {
            // Initialize the Keycloak default crypto provider.
            CryptoIntegration.init(CryptoProvider.class.getClassLoader());

            generateCertificates();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create certificates", e);
        }
    }

    /**
     * Generate certificates.
     *
     * Note:
     * Certificates are needed before running docker compose since Keycloak and Envoy will pick them up only at startup.
     */
    private static void generateCertificates() throws Exception {
        logger.info("Generating certificates...");

        if (!Files.exists(targetDir)) {
            Files.createDirectories(targetDir);
        }

        Credential serverCa = new Credential().subject("CN=server-ca");
        Credential clientCa = new Credential().subject("CN=client-ca");
        Credential untrustedCa = new Credential().subject("CN=untrusted-ca");

        serverCa.writeCertificatesAsPem(targetDir.resolve("server-ca.pem"));
        clientCa.writeCertificatesAsPem(targetDir.resolve("client-ca.pem"));

        new Credential().subject("CN=keycloak")
                .issuer(serverCa)
                .subjectAltNames(Arrays.asList(
                        "DNS:keycloak.127.0.0.1.nip.io", "DNS:keycloak-https.127.0.0.1.nip.io"))
                .writeCertificatesAsPem(targetDir.resolve("keycloak.pem"))
                .writePrivateKeyAsPem(targetDir.resolve("keycloak-key.pem"));

        Credential client = new Credential().subject("CN=client")
                .issuer(clientCa)
                .writeCertificatesAsPem(targetDir.resolve("client.pem"))
                .writePrivateKeyAsPem(targetDir.resolve("client-key.pem"));

        Credential untrusted = new Credential().subject("CN=untrusted-client")
                .issuer(untrustedCa)
                .writeCertificatesAsPem(targetDir.resolve("untrusted-client.pem"))
                .writePrivateKeyAsPem(targetDir.resolve("untrusted-client-key.pem"));

        new Credential().subject("CN=authorized-client").issuer(clientCa)
                .writeCertificatesAsPem(targetDir.resolve("authorized-client.pem"))
                .writePrivateKeyAsPem(targetDir.resolve("authorized-client-key.pem"));

        new Credential().subject("CN=unauthorized-client")
                .issuer(clientCa)
                .writeCertificatesAsPem(targetDir.resolve("unauthorized-client.pem"))
                .writePrivateKeyAsPem(targetDir.resolve("unauthorized-client-key.pem"));

        // Store certificates also to truststore and keystore for the test code to use.
        serverCaStore = KeyStore.getInstance("PKCS12");
        serverCaStore.load(null, null);
        serverCaStore.setCertificateEntry("server-ca", serverCa.getCertificate());

        trustedClientStore = KeyStore.getInstance("PKCS12");
        trustedClientStore.load(null, null);
        trustedClientStore.setCertificateEntry("client", client.getCertificate());
        trustedClientStore.setKeyEntry("client", client.getPrivateKey(), "password".toCharArray(),
                new java.security.cert.Certificate[] { client.getCertificate() });

        untrustedClientStore = KeyStore.getInstance("PKCS12");
        untrustedClientStore.load(null, null);
        untrustedClientStore.setCertificateEntry("untrusted-client", untrusted.getCertificate());
        untrustedClientStore.setKeyEntry("untrusted-client", untrusted.getPrivateKey(), "password".toCharArray(),
                new java.security.cert.Certificate[] { untrusted.getCertificate() });


        // Create a truststore for old Keycloak versions that do not support PEM and write it to a file.
        KeyStore truststoreForClientVerification = KeyStore.getInstance("PKCS12");
        truststoreForClientVerification.load(null, null);
        truststoreForClientVerification.setCertificateEntry("client-ca", clientCa.getCertificate());
        truststoreForClientVerification.store(Files.newOutputStream(targetDir.resolve("client-ca-truststore.p12")),
                "password".toCharArray());
    }

    @RegisterExtension
    public static DockerComposeExtension compose = new DockerComposeExtension(baseDir);

    @BeforeAll
    public static void waitForKeycloak() throws Exception {
        // Wait for Keycloak to be ready.
        WebTarget target = ClientBuilder.newBuilder().trustStore(serverCaStore).build().target(BASE_URL);
        Instant startTime = Instant.now();
        Duration timeout = Duration.ofMinutes(5);

        while (true) {
            logger.infov("Checking Keycloak readiness: url={0}", BASE_URL);

            try {
                Response response = target.request().get();
                if (response.getStatusInfo().getFamily() != Response.Status.Family.SERVER_ERROR) {
                    break;
                }
                logger.infov("Response={0}", response.getStatus());

            } catch (Exception e) {
                logger.infov("Cannot connect: {0}", e.getMessage());
            }

            if (Duration.between(startTime, Instant.now()).compareTo(timeout) > 0) {
                throw new RuntimeException("Keycloak did not start in time");
            }

            Thread.sleep(2500);
        }
    }

    @Test
    public void testAuthenticateWithCert() throws Exception {
        WebTarget target = ClientBuilder.newBuilder()
                .trustStore(serverCaStore)
                .keyStore(trustedClientStore, "password")
                .build().target(BASE_URL + "/realms/xfcc/protocol/openid-connect/token");

        Response response = target.request().post(Entity.form(form));
        String responseBody = response.readEntity(String.class);
        Assertions.assertEquals(200, response.getStatus(), "Failed to fetch token. Response=" + responseBody);

        ObjectMapper mapper = new ObjectMapper();
        JsonNode obj = mapper.readTree(responseBody);
        Assertions.assertTrue(obj.has("access_token"), "Response does not contain access_token");
    }

    @Test
    public void testFailedAuthenticateWithCert() throws Exception {
        WebTarget target = ClientBuilder.newBuilder()
                .trustStore(serverCaStore)
                .keyStore(untrustedClientStore, "password")
                .build().target(BASE_URL + "/realms/xfcc/protocol/openid-connect/token");

        Response response = target.request().post(Entity.form(form));
        String responseBody = response.readEntity(String.class);
        Assertions.assertEquals(401, response.getStatus(), "Was expecting 401 Unauthorized. Response=" + responseBody);
    }

}
