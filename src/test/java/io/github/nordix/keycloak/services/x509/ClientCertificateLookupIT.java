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
import java.nio.file.Paths;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;

import org.jboss.logging.Logger;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
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
@ExtendWith(LoggingExtension.class)
public class ClientCertificateLookupIT {

    private static final String ENVOY_BASE_URL = "https://keycloak.127.0.0.1.nip.io:8443";
    private static final String KEYCLOAK_DIRECT_HTTPS_BASE_URL = "https://keycloak.127.0.0.1.nip.io:10443";
    private static final String KEYCLOAK_DIRECT_HTTP_BASE_URL = "http://keycloak.127.0.0.1.nip.io:10080";

    private static Logger logger = Logger.getLogger(ClientCertificateLookupIT.class);

    private static String baseDir = System.getProperty("user.dir");
    private static Path targetDir = Paths.get(baseDir, "target/certs");

    private static Credential serverCa;
    private static Credential clientCa;

    private static Form form = new Form().param("client_id", "xfcc-client").param("grant_type", "client_credentials");

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
     * Note: Certificates are needed before running docker compose since Keycloak and Envoy will pick them up only at
     * startup.
     */
    private static void generateCertificates() throws Exception {
        logger.info("Generating certificates...");

        if (!Files.exists(targetDir)) {
            Files.createDirectories(targetDir);
        }

        serverCa = new Credential().subject("CN=server-ca").writeCertificatesAsPem(targetDir.resolve("server-ca.pem"));
        clientCa = new Credential().subject("CN=client-ca").writeCertificatesAsPem(targetDir.resolve("client-ca.pem"));

        // Create a truststore for old Keycloak versions that do not support PEM and write it to a file.
        Helpers.newTrustStore(clientCa).store(Files.newOutputStream(targetDir.resolve("client-ca-truststore.p12")),
                Helpers.STORE_PASSWORD.toCharArray());

        new Credential().subject("CN=keycloak").issuer(serverCa)
                .subjectAltNames(Arrays.asList("DNS:keycloak.127.0.0.1.nip.io", "DNS:keycloak-https.127.0.0.1.nip.io"))
                .writeCertificatesAsPem(targetDir.resolve("keycloak.pem"))
                .writePrivateKeyAsPem(targetDir.resolve("keycloak-key.pem"));

        new Credential().subject("CN=envoy-client").issuer(clientCa)
                .writeCertificatesAsPem(targetDir.resolve("envoy-client.pem"))
                .writePrivateKeyAsPem(targetDir.resolve("envoy-client-key.pem"));

    }

    @RegisterExtension
    public static DockerComposeExtension compose = new DockerComposeExtension(baseDir);

    @BeforeAll
    public static void waitForKeycloak() throws Exception {
        // Wait for Keycloak to be ready.
        WebTarget target = newTargetNoClientAuth(ENVOY_BASE_URL);
        Instant startTime = Instant.now();
        Duration timeout = Duration.ofMinutes(5);

        while (true) {
            logger.infov("Checking Keycloak readiness: url={0}", ENVOY_BASE_URL);

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

    /**
     * 1. External client connects to Envoy using TLS and client certificate (CN=authorized-client).
     * 2. Envoy connects to Keycloak using TLS and client certificate (CN=envoy-client).
     * 3. Keycloak accepts the TLS connection, authenticated with the client certificate (CN=envoy-client).
     * 4. Envoy forwards the client request to Keycloak with XFCC header set to the client certificate (CN=authorized-client).
     * 5. Envoy X509 Lookup verifies that TLS level client certificate matches the configured certificate path (CN=envoy-client).
     * 6. Envoy X509 Lookup returns client certificate from XFCC to Keycloak (CN=authorized-client).
     * 7. Keycloak X509 Authenticator accepts request (CN=authorized-client) and returns the token.
     */
    @Test
    void testEnvoyAuthorizedClientCert() throws Exception {
        Credential tlsCred = new Credential().subject("CN=authorized-client").issuer(clientCa);

        WebTarget target = newTargetWithClientAuth(ENVOY_BASE_URL + "/realms/xfcc/protocol/openid-connect/token",
                tlsCred);

        Response response = target.request().post(Entity.form(form));
        String responseBody = response.readEntity(String.class);
        Assertions.assertEquals(200, response.getStatus(), "Failed to fetch token. Response=" + responseBody);

        ObjectMapper mapper = new ObjectMapper();
        JsonNode obj = mapper.readTree(responseBody);
        Assertions.assertTrue(obj.has("access_token"), "Response does not contain access_token");
    }

    /**
     * 1. External client connects to Envoy using TLS and client certificate (CN=unauthorized-client).
     * 2. Envoy connects to Keycloak using TLS and client certificate (CN=envoy-client).
     * 3. Keycloak accepts the TLS connection, authenticated with the client certificate (CN=envoy-client).
     * 4. Envoy forwards the client request to Keycloak with XFCC header set to the client certificate (CN=unauthorized-client).
     * 5. Envoy X509 Lookup verifies that TLS level client certificate matches the configured certificate path (CN=envoy-client).
     * 6. Envoy X509 Lookup returns client certificate from XFCC to Keycloak (CN=unauthorized-client).
     * 7. Keycloak X509 Authenticator rejects the request since it has wrong subject name (CN=authorized-client).
     */
    @Test
    void testEnvoyUnauthorizedClientCert() throws Exception {
        Credential tlsCred = new Credential().subject("CN=unauthorized-client").issuer(clientCa);

        WebTarget target = newTargetWithClientAuth(ENVOY_BASE_URL + "/realms/xfcc/protocol/openid-connect/token",
                tlsCred);

        Response response = target.request().post(Entity.form(form));
        String responseBody = response.readEntity(String.class);
        Assertions.assertEquals(401, response.getStatus(), "Was expecting 401 Unauthorized. Response=" + responseBody);
    }

    /**
     * 1. External client connects to Envoy using plain HTTP.
     * 2. Envoy connects to Keycloak using TLS and client certificate (CN=envoy-client).
     * 3. Keycloak accepts the TLS connection, authenticated with the client certificate (CN=envoy-client).
     * 4. Envoy forwards the client request to Keycloak with no XFCC header.
     * 5. Envoy X509 Lookup verifies that TLS level client certificate matches the configured certificate path (CN=envoy-client).
     * 6. Envoy X509 Lookup returns null since the request has no XFCC header even though request came from Envoy (CN=envoy-client).
     * 7. Keycloak X509 Authenticator rejects the request since lookup did not return a client certificate.
     */
    @Test
    void testEnvoyWithoutClientCert() throws Exception {
        WebTarget target = newTargetNoClientAuth(ENVOY_BASE_URL + "/realms/xfcc/protocol/openid-connect/token");

        Response response = target.request().post(Entity.form(form));
        String responseBody = response.readEntity(String.class);
        Assertions.assertEquals(401, response.getStatus(), "Was expecting 401 Unauthorized. Response=" + responseBody);
    }

    /**
     * 1. Cluster internal client connects to Keycloak using plain HTTP.
     * 2. Client sends request with XFCC header with client certificate (CN=authorized-client).
     * 3. Envoy X509 Lookup verifies if TLS level client certificate matches the configured certificate path (CN=envoy-client).
     * 4. Envoy X509 Lookup returns null since the request is not over TLS.
     * 5. Keycloak X509 Authenticator rejects the request since lookup did not return a client certificate.
     */
    @Test
    void testInternalClientHttpUnauthorizedXfcc() throws Exception {
        Credential xfccCred = new Credential().subject("CN=authorized-client").issuer(clientCa);

        WebTarget target = newTargetNoClientAuth(
                KEYCLOAK_DIRECT_HTTP_BASE_URL + "/realms/xfcc/protocol/openid-connect/token");

        Response response = target.request().header("x-forwarded-client-cert", Helpers.getXfccWithCert(xfccCred))
                .post(Entity.form(form));
        String responseBody = response.readEntity(String.class);
        Assertions.assertEquals(401, response.getStatus(), "Was expecting 401 Unauthorized. Response=" + responseBody);
    }

    /**
     * 1. Cluster internal client connects to Keycloak directly using TLS and client certificate (CN=not-envoy).
     * 2. Client sends request with XFCC header with client certificate (CN=authorized-client).
     * 3. Envoy X509 Lookup verified if TLS level client certificate matches the configured certificate path (CN=envoy-client).
     * 4. Envoy X509 Lookup returns null since client (CN=not-envoy) is not authorized to send the XFCC header.
     * 5. Keycloak X509 Authenticator rejects the request since lookup did not return a client certificate.
     */
    @Test
    void testInternalClientHttpsUnauthorizedXfcc() throws Exception {
        Credential tlsCred = new Credential().subject("CN=not-envoy").issuer(clientCa);
        Credential xfccCred = new Credential().subject("CN=authorized-client").issuer(clientCa);

        WebTarget target = newTargetWithClientAuth(
                KEYCLOAK_DIRECT_HTTP_BASE_URL + "/realms/xfcc/protocol/openid-connect/token", tlsCred);

        Response response = target.request().header("x-forwarded-client-cert", Helpers.getXfccWithCert(xfccCred))
                .post(Entity.form(form));

        String responseBody = response.readEntity(String.class);
        Assertions.assertEquals(401, response.getStatus(), "Was expecting 401 Unauthorized. Response=" + responseBody);
    }

    /**
     * 1. Cluster internal client connects to Keycloak directly using TLS and client certificate (CN=authorized-client).
     * 2. Client sends request without XFCC header.
     * 3. Client X509 Lookup verifies if TLS level client certificate matches the configured certificate path (CN=envoy-client), it does not.
     * 4. Client X509 Lookup returns the client certificate from TLS layer (CN=authorized-client).
     * 5. Keycloak X509 Authenticator accepts request (CN=authorized-client) and returns the token.
     */
    @Test
    void TestInternalClientHttpsAuthorized() throws Exception {
        Credential tlsCred = new Credential().subject("CN=authorized-client").issuer(clientCa);

        WebTarget target = newTargetWithClientAuth(
                KEYCLOAK_DIRECT_HTTPS_BASE_URL + "/realms/xfcc/protocol/openid-connect/token", tlsCred);

        Response response = target.request().post(Entity.form(form));
        String responseBody = response.readEntity(String.class);
        Assertions.assertEquals(200, response.getStatus(), "Failed to fetch token. Response=" + responseBody);

        ObjectMapper mapper = new ObjectMapper();
        JsonNode obj = mapper.readTree(responseBody);
        Assertions.assertTrue(obj.has("access_token"), "Response does not contain access_token");
    }

    // Helper methods

    static WebTarget newTargetNoClientAuth(String url)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        return ClientBuilder.newBuilder().trustStore(Helpers.newTrustStore(serverCa)).build().target(url);
    }

    static WebTarget newTargetWithClientAuth(String url, Credential clientCred)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        return ClientBuilder.newBuilder().trustStore(Helpers.newTrustStore(serverCa))
                .keyStore(Helpers.newKeyStore(clientCred), Helpers.STORE_PASSWORD).build().target(url);
    }
}
