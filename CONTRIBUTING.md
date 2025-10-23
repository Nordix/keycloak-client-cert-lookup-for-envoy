# Contributing

This guide is for those who wish to contribute to the project.

## Development

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
