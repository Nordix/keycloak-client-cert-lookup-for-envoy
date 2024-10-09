# Keycloak X509 client certificate lookup SPI for Envoy

This project provides an X509 client certificate lookup SPI for Keycloak.
It enables Keycloak to retrieve the client certificate from the `x-forwarded-client-cert` (XFCC) header set by Envoy and use it for authentication.

For more details, refer to https://www.keycloak.org/server/reverseproxy and the section "Enabling client certificate lookup".


## Compiling

To compile the project, run the following command:

```shell
mvn clean package
```
