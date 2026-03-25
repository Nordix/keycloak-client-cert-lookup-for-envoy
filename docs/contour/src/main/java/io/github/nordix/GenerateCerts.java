package io.github.nordix;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;

import fi.protonode.certy.Credential;

public class GenerateCerts {

    public static void main(String[] args) throws CertificateException, NoSuchAlgorithmException, IOException {

        Path basePath = Paths.get("target/certs");
        if (!basePath.toFile().exists()) {
            basePath.toFile().mkdirs();
        }

        // CA certificates.
        Credential clusterExternalCa = new Credential().subject("CN=cluster-external-ca")
                .writeCertificatesAsPem(basePath.resolve("cluster-external-ca.pem"));

        Credential clusterInternalCa = new Credential().subject("CN=cluster-internal-ca")
                .writeCertificatesAsPem(basePath.resolve("cluster-internal-ca.pem"));

        // Ingress controller certificate for Contour TLS termination (external facing).
        new Credential().subject("CN=ingress-controller").issuer(clusterExternalCa)
                .subjectAltName("DNS:keycloak.127.0.0.1.nip.io")
                .writeCertificatesAsPem(basePath.resolve("ingress-controller.pem"))
                .writePrivateKeyAsPem(basePath.resolve("ingress-controller-key.pem"));

        // Keycloak HTTPS certificate (internal, for Envoy -> Keycloak upstream TLS).
        new Credential().subject("CN=keycloak").issuer(clusterInternalCa)
                .subjectAltNames(Arrays.asList("DNS:keycloak", "DNS:keycloak.default.svc.cluster.local"))
                .writeCertificatesAsPem(basePath.resolve("keycloak.pem"))
                .writePrivateKeyAsPem(basePath.resolve("keycloak-key.pem"));

        // External client certificate.
        new Credential().subject("CN=authorized-client").issuer(clusterExternalCa)
                .writeCertificatesAsPem(basePath.resolve("external-client.pem"))
                .writePrivateKeyAsPem(basePath.resolve("external-client-key.pem"));

        // Envoy client certificate (internal for Envoy upstream, mutual TLS auth towards Keycloak).
        new Credential().subject("CN=envoy-client").issuer(clusterInternalCa)
                .writeCertificatesAsPem(basePath.resolve("envoy-client.pem"))
                .writePrivateKeyAsPem(basePath.resolve("envoy-client-key.pem"));
    }
}
