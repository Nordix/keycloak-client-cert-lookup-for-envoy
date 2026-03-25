# Demo: Keycloak Client Certificate Lookup for Contour / Envoy

## Introduction

This guide provides steps to deploy a demo where Contour authenticates the client using an X509 client certificate and forwards the certificate to Keycloak using Envoy XFCC (X-Forwarded-Client-Cert) HTTP header.
Keycloak is configured with the Client Certificate Lookup extension for Envoy, which parses the client certificate and uses it for authentication.

This demo also demonstrates the XFCC authorization feature of the provider: Envoy is configured with a client certificate for upstream connections to Keycloak, and Keycloak is configured to only accept XFCC headers from clients presenting the expected certificate (`CN=envoy-client`).
This prevents internal clients from spoofing XFCC headers.
For more information, see [Understanding Client Certificate Forwarding and Security Implications](../security-and-client-cert-forwarding.md).

## Installation

First compile the extension (from the project top directory):

```
cd TOP_DIR
./mvnw clean package -Dmaven.test.skip
```

Start Kind cluster (execute the command in the directory where this README is located):

```
cd docs/contour
kind create cluster --config configs/kind-cluster-config.yaml --name keycloak-client-cert-lookup-for-envoy
```

Install Contour:

```
kubectl apply -f https://projectcontour.io/quickstart/contour.yaml
```

Patch the Envoy DaemonSet to use `hostPort` so that Envoy is accessible from the host:

```
kubectl -n projectcontour patch daemonset envoy --type=json -p='[
  {"op": "add", "path": "/spec/template/spec/containers/1/ports/1/hostPort", "value": 8443}
]'
```

## Configuration

Generate certificates for testing:

```
mvn compile exec:java -Dexec.mainClass="io.github.nordix.GenerateCerts"
```

Create secrets for the HTTPProxy TLS termination and client certificate validation (in `default` namespace):

```
kubectl create secret tls server-cert \
  --cert=target/certs/server.pem \
  --key=target/certs/server-key.pem --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic client-ca \
  --from-file=ca.crt=target/certs/client-ca.pem --dry-run=client -o yaml | kubectl apply -f -
```

Create secret for upstream TLS validation (Envoy validates Keycloak's HTTPS certificate):

```
kubectl create secret generic server-ca \
  --from-file=ca.crt=target/certs/server-ca.pem --dry-run=client -o yaml | kubectl apply -f -
```

Create secret for the Envoy client certificate used for upstream mutual TLS to Keycloak (in `projectcontour` namespace):

```
kubectl -n projectcontour create secret tls envoy-client-cert \
  --cert=target/certs/envoy-client.pem \
  --key=target/certs/envoy-client-key.pem --dry-run=client -o yaml | kubectl apply -f -
```

Apply the Contour configuration to enable the Envoy client certificate for upstream connections, then restart Contour:

```
kubectl apply -f manifests/contour-config.yaml
kubectl -n projectcontour rollout restart deployment/contour
```

Deploy Keycloak with the Envoy client certificate lookup provider to `default` namespace:

```
kubectl apply -f manifests/keycloak.yaml
```

Create HTTPProxy to `default` namespace:

```
kubectl apply -f manifests/httpproxy.yaml
```

## Usage

You can now access Keycloak at https://keycloak.127.0.0.1.nip.io:8443/.
The username is `admin` and the password is `admin`.

To fetch token by using the X509 certificate client authentication, you can use the following command (using [httpie](https://httpie.io/)):

```
http --verbose --form --verify=target/certs/server-ca.pem --cert=target/certs/client.pem --cert-key=target/certs/client-key.pem POST https://keycloak.127.0.0.1.nip.io:8443/realms/xfcc/protocol/openid-connect/token client_id=xfcc-client grant_type=client_credentials
```

If you do not get a token, wait a few seconds and try again.
The Keycloak pod may not be ready yet.

## Cleanup

Delete the Kind cluster:

```
kind delete cluster --name keycloak-client-cert-lookup-for-envoy
```
