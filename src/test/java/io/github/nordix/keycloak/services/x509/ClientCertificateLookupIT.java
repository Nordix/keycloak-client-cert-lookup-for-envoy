/**
 * Copyright (c) 2024 OpenInfra Foundation Europe and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License, Version 2.0
 * which accompanies this distribution, and is available at
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package io.github.nordix.keycloak.services.x509;

import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.jboss.logging.Logger;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.crypto.CryptoProvider;

import fi.protonode.certy.Credential;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.Form;
import jakarta.ws.rs.core.Response;

public class ClientCertificateLookupIT {

    private static final String baseUrl = "https://keycloak.127.0.0.1.nip.io:8443";
    private static final Logger logger = Logger.getLogger(ClientCertificateLookupIT.class);

    private static String baseDir = System.getProperty("user.dir");
    private static Path targetDir = Paths.get(baseDir, "target/certs");

    private static Form form = new Form()
            .param("client_id", "xfcc-client")
            .param("grant_type", "client_credentials");

    // Generate certificates before running docker compose.
    static {
        try {
            // Initialize the Keycloak default crypto provider.
            CryptoIntegration.init(CryptoProvider.class.getClassLoader());

            // Generate certificates.
            logger.info("Generating certificates...");

            Credential serverCa = new Credential().subject("CN=server-ca");
            Credential keycloak = new Credential().subject("CN=keycloak")
                    .issuer(serverCa)
                    .subjectAltName("DNS:keycloak.127.0.0.1.nip.io");

            Credential clientCa = new Credential().subject("CN=client-ca");
            Credential client = new Credential().subject("CN=client")
                    .issuer(clientCa);

            Credential untrustedCa = new Credential().subject("CN=untrusted-ca");
            Credential untrusted = new Credential().subject("CN=untrusted-client")
                    .issuer(untrustedCa);

            // Save certificates to disk for Envoy container to use.
            if (!Files.exists(targetDir)) {
                Files.createDirectories(targetDir);
            }

            serverCa.writeCertificatesAsPem(targetDir.resolve("server-ca.pem"));
            clientCa.writeCertificatesAsPem(targetDir.resolve("client-ca.pem"));

            keycloak.writeCertificatesAsPem(targetDir.resolve("keycloak.pem"));
            keycloak.writePrivateKeyAsPem(targetDir.resolve("keycloak-key.pem"));

            client.writeCertificatesAsPem(targetDir.resolve("client.pem"));
            client.writePrivateKeyAsPem(targetDir.resolve("client-key.pem"));

            untrusted.writeCertificatesAsPem(targetDir.resolve("untrusted-client.pem"));
            untrusted.writePrivateKeyAsPem(targetDir.resolve("untrusted-client-key.pem"));
        } catch (Exception e) {
            throw new RuntimeException("Failed to create target directory", e);
        }

    }

    @RegisterExtension
    public static DockerComposeExtension compose = new DockerComposeExtension(baseDir);

    @BeforeAll
    public static void waitForKeycloak() throws Exception {
        // Wait for Keycloak to be ready.
        WebTarget target = client(targetDir.resolve("server-ca.pem")).target(baseUrl);

        while (true) {
            logger.infov("Checking Keycloak readiness: url={0}", baseUrl);

            try {
                Response response = target.request().get();
                if (response.getStatusInfo().getFamily() != Response.Status.Family.SERVER_ERROR) {
                    break;
                }
                logger.infov("Response={0}", response.getStatus());

            } catch (Exception e) {
                logger.infov("Cannot connect: {0}", e.getMessage());
            }
            Thread.sleep(2500);
        }
    }

    @Test
    public void testAuthenticateWithCert() throws Exception {
        WebTarget target = clientWithCredentials(
                targetDir.resolve("server-ca.pem"),
                targetDir.resolve("client.pem"),
                targetDir.resolve("client-key.pem"))
                .target(baseUrl + "/realms/xfcc/protocol/openid-connect/token");

        Response response = target.request().post(Entity.form(form));
        String responseBody = response.readEntity(String.class);
        Assertions.assertEquals(200, response.getStatus(), "Failed to fetch token. Response=" + responseBody);
        JsonObject obj = Json.createReader(new StringReader(responseBody)).readObject();
        Assertions.assertTrue(obj.containsKey("access_token"), "Response does not contain access_token");
    }

    @Test
    public void testFailedAuthenticateWithCert() throws Exception {
        Client client = clientWithCredentials(
                targetDir.resolve("server-ca.pem"),
                targetDir.resolve("untrusted-client.pem"),
                targetDir.resolve("untrusted-client-key.pem"));

        WebTarget target = client.target(baseUrl + "/realms/xfcc/protocol/openid-connect/token");

        Response response = target.request().post(Entity.form(form));
        String responseBody = response.readEntity(String.class);
        Assertions.assertEquals(401, response.getStatus(), "Was expecting 401 Unauthorized. Response=" + responseBody);
    }

    private static Client client(Path caPath) throws Exception {
        return ClientBuilder.newBuilder()
                .trustStore(CertificateUtils.loadTrustedCertificate(caPath))
                .build();
    }

    private static Client clientWithCredentials(Path caPath, Path certPath, Path keyPath) throws Exception {
        return ClientBuilder.newBuilder()
                .trustStore(CertificateUtils.loadTrustedCertificate(caPath))
                .keyStore(CertificateUtils.loadCredentials(certPath, keyPath, "password"), "password")
                .build();
    }

}
