# Keycloak X509 Client Certificate Lookup SPI for Envoy

This project provides an X509 client certificate lookup SPI for Keycloak.
It allows Keycloak to retrieve the client certificate from the `x-forwarded-client-cert` (XFCC) header set by Envoy and use it for authentication.

For more information, refer to [Keycloak's reverse proxy documentation](https://www.keycloak.org/server/reverseproxy) and the section "Enabling client certificate lookup".


## Installation

This project is not available in Maven Central, so you need to build it locally.
To compile the project, run the following command:

```
./mvnw clean package
```

The JAR file will be generated in the target directory.
Copy the JAR file to your Keycloak distribution directory, under the providers directory.
In the Keycloak release Docker image, copy the JAR file to the `/opt/keycloak/providers/` directory.
See Keycloak's [Configuring Providers](https://www.keycloak.org/server/configuration-provider) documentation for more details.


## Why this project?

The extension was submitted as a pull request [keycloak#33159](https://github.com/keycloak/keycloak/pull/33159) but client certificate lookup implementations for new proxies are no longer accepted.
Instead, implementations are encouraged to be developed as extensions.

This project uses private Keycloak APIs to implement the lookup SPI, which are not guaranteed to be stable across Keycloak versions.


## Development

To run unit tests, use the following command:

```
./mvnw clean test
```

Integration tests use Docker Compose to start Keycloak and Envoy, so ensure Docker is installed.
To run integration tests, use the following command:

```
./mvnw clean verify
```
