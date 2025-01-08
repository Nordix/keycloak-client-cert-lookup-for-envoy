package io.github.nordix;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import fi.protonode.certy.Credential;

public class GenerateCerts {

    public static void main(String[] args) throws CertificateException, NoSuchAlgorithmException, IOException {

        // Create directory for the certificates
        String path = "target/certs";
        Path basePath = Paths.get(path);
        if (!basePath.toFile().exists()) {
            basePath.toFile().mkdirs();
        }

        // Generate CA certificates
        Credential serverCa = new Credential().subject("CN=server-ca")
                .writeCertificatesAsPem(basePath.resolve("server-ca.pem"));

        Credential clientCa = new Credential().subject("CN=client-ca")
                .writeCertificatesAsPem(basePath.resolve("client-ca.pem"));

        // Generate end-entity certificates
        new Credential().subject("CN=server")
                .issuer(serverCa)
                .subjectAltName("DNS:keycloak.127.0.0.1.nip.io")
                .writeCertificatesAsPem(basePath.resolve("server.pem"))
                .writePrivateKeyAsPem(basePath.resolve("server-key.pem"));

        new Credential().subject("CN=authorized-client")
                .issuer(clientCa)
                .writeCertificatesAsPem(basePath.resolve("client.pem"))
                .writePrivateKeyAsPem(basePath.resolve("client-key.pem"));
    }
}
