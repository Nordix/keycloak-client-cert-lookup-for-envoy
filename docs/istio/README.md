# Demo: Keycloak Client Certificate Lookup for Istio / Envoy

## Introduction

This guide provides steps to deploy a demo where Istio authenticates the client using an X509 client certificate and forwards the certificate to Keycloak using Envoy XFCC (X-Forwarded-Client-Cert) HTTP header.
Keycloak is configured with the Client Certificate Lookup extension for Envoy, which parses the client certificate and uses it for authentication.

## Installation

First compile the extension (from the project top directory):

```
cd TOP_DIR
./mvnw clean package
```

Start Kind cluster (execute the command in the directory where this README is located):

```
cd docs/istio
kind create cluster --config configs/kind-cluster-config.yaml --name keycloak-client-cert-lookup-for-envoy
```

Download Istio:

```
curl -L https://github.com/istio/istio/releases/download/1.24.2/istio-1.24.2-linux-amd64.tar.gz -o istio.tar.gz
tar -xzf istio.tar.gz
```

Install Istio to the Kind cluster.

```
export PATH=$PATH:$(cd istio-*/bin; pwd)
istioctl install --skip-confirmation --filename configs/istio-config.yaml
```

## Configuration

Enable Istio sidecar injection for the `default` namespace where Keycloak will be deployed:

```
kubectl label namespace default istio-injection=enabled
```

Generate certificates for testing:

```
mvn compile exec:java -Dexec.mainClass="io.github.nordix.GenerateCerts"
```

Create secret for Istio Gateway (in `istio-system` namespace):

```
kubectl -n istio-system create secret generic ingress-cert \
  --from-file=tls.crt=target/certs/server.pem \
  --from-file=tls.key=target/certs/server-key.pem \
  --from-file=ca.crt=target/certs/client-ca.pem --dry-run=client -o yaml | kubectl apply -f -
```

Deploy Keycloak with the Envoy extension to `default` namespace:

```
kubectl apply -f manifests/keycloak.yaml
```

Create Istio Gateway and VirtualService to `default` namespace:

```
kubectl apply -f manifests/istio.yaml
```

## Usage

You can now access Keycloak at https://keycloak.127.0.0.1.nip.io:8443/.
The username is `admin` and the password is `admin`.

To fetch token by using the X509 certificate client authentication, you can use the following command (using [httpie](https://httpie.io/)):

```console
$ http --verbose --form --verify=target/certs/server-ca.pem --cert=target/certs/client.pem --cert-key=target/certs/client-key.pem POST https://keycloak.127.0.0.1.nip.io:8443/realms/xfcc/protocol/openid-connect/token client_id=xfcc-client grant_type=client_credentials
POST /realms/xfcc/protocol/openid-connect/token HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Content-Length: 51
Content-Type: application/x-www-form-urlencoded; charset=utf-8
Host: keycloak.127.0.0.1.nip.io:8443
User-Agent: HTTPie/3.2.2

client_id=xfcc-client&grant_type=client_credentials


HTTP/1.1 200 OK
cache-control: no-store
content-length: 1422
content-type: application/json
date: Wed, 08 Jan 2025 08:43:41 GMT
pragma: no-cache
referrer-policy: no-referrer
server: istio-envoy
strict-transport-security: max-age=31536000; includeSubDomains
x-content-type-options: nosniff
x-envoy-upstream-service-time: 6
x-frame-options: SAMEORIGIN
x-xss-protection: 1; mode=block

{
    "access_token": "<token redacted>",
    "expires_in": 300,
    "not-before-policy": 0,
    "refresh_expires_in": 0,
    "scope": "profile email",
    "token_type": "Bearer"
}
```

If you do not get a token, wait a few seconds and try again.
The Keycloak pod may not be ready yet.

## Cleanup

Delete the Kind cluster:

```
kind delete cluster --name keycloak-client-cert-lookup-for-envoy
```
