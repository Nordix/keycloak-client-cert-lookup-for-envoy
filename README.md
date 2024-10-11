# Keycloak X509 Client Certificate Lookup for Envoy

This project provides an X509 client certificate lookup implementation for [Envoy proxy](https://www.envoyproxy.io/).
It allows Keycloak to retrieve the client certificate from the `x-forwarded-client-cert` (XFCC) header set by Envoy and use it for authorization.
For more information, refer to [Keycloak's reverse proxy documentation](https://www.keycloak.org/server/reverseproxy) and the section [Enabling client certificate lookup](https://www.keycloak.org/server/reverseproxy#_enabling_client_certificate_lookup).
See also [Envoy's documentation](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert) on XFCC header.

See [Configuring Kubernetes Ingress Controllers for Client Certificate Forwarding](docs/ingress-controllers.md) for more information on how to configure Kubernetes ingress controllers for client certificate forwarding.

> ⚠️ **Alert:** There are implications that you should be aware of when enabling client certificate lookup in Keycloak.
For more information, see [Understanding Client Certificate Forwarding and Security Implications](docs/security-and-client-cert-forwarding.md).

This project was created because the code submitted in [keycloak#33159](https://github.com/keycloak/keycloak/pull/33159) was not accepted.
Instead, Keycloak encourages the development of implementations for different proxies as extensions.

## Installation

This project is not available on Maven Central.
To compile it locally, ensure you have JDK and Git installed.
Clone the repository and execute:

```
./mvnw clean package
```

The JAR file will be created in the `target` directory.
Copy the JAR file to the `providers` directory in your Keycloak distribution.
For instance, in the official Keycloak Docker image releases, place the JAR file in the `/opt/keycloak/providers/`.
Add following command line parameter to `kc.sh` to choose the provider:

```
--spi-x509cert-lookup-provider=envoy
```

Restart Keycloak for the changes to take effect.
You will see a warning in the logs when the JAR file is loaded:

```
2024-10-11 09:15:29,052 WARN  [org.key.services] (build-13) KC-SERVICES0047: envoy (io.github.nordix.keycloak.services.x509.EnvoyProxySslClientCertificateLookupFactory) is implementing the internal SPI x509cert-lookup. This SPI is internal and may change without notice
```

This warning is expected, since the X509 client certificate lookup SPI is not guaranteed to be stable across Keycloak versions.
This project may require updates for newer Keycloak versions.

Refer to Keycloak's [Configuring Providers](https://www.keycloak.org/server/configuration-provider) documentation for more information.


## Development

This section is for developers who wish to contribute to the project.

To run unit tests, use:

```
./mvnw clean test
```

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
