# Keycloak X509 Client Certificate Lookup for Envoy

This project provides an X509 client certificate lookup implementation for [Envoy proxy](https://www.envoyproxy.io/).
It allows Keycloak to retrieve the client certificate from the `x-forwarded-client-cert` (XFCC) header set by Envoy and use it for authorization.

This project was created because the code submitted in [keycloak#33159](https://github.com/keycloak/keycloak/pull/33159) was not accepted.
Instead, Keycloak encourages the development of implementations for different proxies as extensions.
However, `x509cert-lookup` SPI is considered internal and may change without prior notice.
A request to make this SPI stable has been submitted here: [keycloak#33818](https://github.com/keycloak/keycloak/issues/33818).

> ⚠️ **Alert:** There are implications that you should be aware of when enabling client certificate lookup in Keycloak.
For more information, see [Understanding Client Certificate Forwarding and Security Implications](docs/security-and-client-cert-forwarding.md).

## Installation

This project is not available on Maven Central.
To compile it locally, ensure you have JDK and Git installed.
Clone the repository and execute:

```
./mvnw clean package -DskipTests=true
```

The JAR file will be created in the `target` directory.
Copy the JAR file to the `providers` directory in your Keycloak distribution.
For instance, in the official Keycloak Docker image releases, place the JAR file in the `/opt/keycloak/providers/`.

## Configuration

For information on how to use the project, refer to the following documents:

* See [here](docs/ingress-controllers.md) on how to configure Kubernetes ingress controllers for client certificate forwarding.
* For more information on the Keycloak feature, refer to [Keycloak's reverse proxy documentation](https://www.keycloak.org/server/reverseproxy) and the section [Enabling client certificate lookup](https://www.keycloak.org/server/reverseproxy#_enabling_client_certificate_lookup).
* See also [Envoy's documentation](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert) on XFCC header.
* If you're enabling [authorization](#authorizing-clients-that-are-allowed-to-send-xfcc-headers-optional) for the XFCC header, configure the CA certificates using `https-trust-store` to validate the client, and set `https-client-auth` to `request` so that Keycloak optionally requests a client certificate. Follow the Keycloak guide on [Configuring trusted certificates for mTLS](https://www.keycloak.org/server/mutual-tls) for detailed instructions.



### Enable client certificate lookup (mandatory)

Add the following command line parameter to `kc.sh` to choose the provider:

```
--spi-x509cert-lookup-provider=envoy
```

Alternatively, you can set the environment variable `KC_SPI_X509CERT_LOOKUP_PROVIDER=envoy` or specify `spi-x509cert-lookup-provider=envoy` in the Keycloak configuration file.

Restart Keycloak for the changes to take effect.
You will see a warning in the logs when the JAR file is loaded:

```
2024-10-11 09:15:29,052 WARN  [org.key.services] (build-13) KC-SERVICES0047: envoy (io.github.nordix.keycloak.services.x509.EnvoyProxySslClientCertificateLookupFactory) is implementing the internal SPI x509cert-lookup. This SPI is internal and may change without notice
```

This warning is expected, since the X509 client certificate lookup SPI is not guaranteed to be stable across Keycloak versions.
This project may require updates for newer Keycloak versions.

Refer to Keycloak's [Configuring Providers](https://www.keycloak.org/server/configuration-provider) documentation for more information.


### Authorizing clients that are allowed to send XFCC headers (optional)

If Keycloak is deployed in an environment where some clients must bypass the proxy, it is important to ensure that only Envoy can send XFCC headers.
This prevents clients from impersonating other users by sending XFCC headers.
For more information on this, refer to [Understanding Client Certificate Forwarding and Security Implications](docs/security-and-client-cert-forwarding.md).

Prerequisites:

* Envoy must use TLS and client certificate authentication for its connection to Keycloak.
* X509 Client Certificate Lookup for Envoy must be configured with the list of expected subject names for clients that are allowed to send XFCC headers.

The list is configured as a command line parameter to `kc.sh` in the following format:

```
--spi-x509cert-lookup-envoy-cert-path-verify='[[ "<leaf-subject>", "<intermediate-subject>", ... ], ... ]'
```

Alternatively, you can set the environment variable `KC_SPI_X509CERT_LOOKUP_ENVOY_CERT_PATH_VERIFY=[[ "CN=envoy" ]]` or specify `spi-x509cert-lookup-envoy-cert-path-verify=[[ "CN=envoy" ]]` in the Keycloak configuration file.

The parameter is optional and its behavior is as follows:

| Parameter value | Description | Example |
| --- | --- | --- |
| Not set | XFCC header will be processed from any client. | N/A |
| Empty array | XFCC header will not be processed from any client. | `--spi-x509cert-lookup-envoy-cert-path-verify='[]'` |
| Non-empty array | XFCC header will be processed only if the TLS-level client certificate chain matches the specified subject names. | `--spi-x509cert-lookup-envoy-cert-path-verify='[[ "CN=envoy" ]]'` |

The parameter value is a JSON array of arrays.
Each inner array represents a certificate chain, with the first element as the leaf certificate's subject name and subsequent elements as intermediate certificates.
Root certificates should not be included.
For example, to allow a client certificate chain with the subject name `CN=envoy, O=example.com` and an intermediate certificate with the subject name `CN=intermediate, O=example.com`, use:

```
--spi-x509cert-lookup-envoy-cert-path-verify='[[ "CN=envoy, O=example.com", "CN=intermediate, O=example.com" ]]'
```

The subject names must match exactly, as X500 Distinguished Names are order-sensitive (`CN=envoy, O=example.com` is not the same as `O=example.com, CN=envoy`).
The path can be partial: verification succeeds if the expected subject names are found in order, even if the received chain has additional certificates.


## Development

This section is for developers who wish to contribute to the project.

To run unit tests, use:

```
./mvnw clean test
```

The coverage report is generated in `target/site/jacoco/index.html`.

Integration tests require Docker Compose to start Keycloak and Envoy.
Ensure Docker is installed.
To run integration tests, use:

```
./mvnw clean verify
```

To run checkstyle, use:

```
./mvnw checkstyle:check
```
