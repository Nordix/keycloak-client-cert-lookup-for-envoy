# Configuring Kubernetes Ingress Controllers for Client Certificate Forwarding

This guide demonstrates how to configure Contour and Istio for optional client certificate validation and forward the client certificate to Keycloak.
This setup allows Keycloak to determine when a client certificate is required, while keeping the Keycloak UI, like the login page, accessible without a certificate.

### Contour

To enable optional client certificate validation and forward the certificate to Keycloak, configure the Contour `HTTPProxy` resource as follows:

```yaml
apiVersion: projectcontour.io/v1
kind: HTTPProxy
metadata:
  name: keycloak
spec:
  virtualhost:
    fqdn: keycloak.127-0-0-121.nip.io
    tls:
      secretName: keycloak-external
      clientValidation:
        caSecret: client-ca
        optionalClientCertificate: true
        forwardClientCertificate:
          cert: true
  routes:
    - services:
        - name: keycloak
          port: 8080
```


### Istio

By default, the Istio ingress gateway sends the XFCC header, which includes the Cert parameter with the client certificate.
To enable optional client certificate validation, configure the `Gateway` with `mode: OPTIONAL_MUTUAL`.
The associated secret must contain the CA certificate (`ca.crt`) for client certificate validation, along with the TLS server certificate and private key.


```yaml
apiVersion: networking.istio.io/v1
kind: Gateway
metadata:
  name: mygateway
spec:
  selector:
    istio: ingressgateway
  servers:
  - port:
      number: 80
      name: http
      protocol: HTTP
    hosts:
    - "*"
  - port:
      number: 443
      name: https
      protocol: HTTPS
    tls:
      mode: OPTIONAL_MUTUAL
      credentialName: keycloak-external
    hosts:
    - "*"
```


### Keycloak Configuration

To configure a client with the X509 authenticator, create a new client with the following settings:

1. In the "General settings" step, fill in:
    - Set the Client ID name, for example: `x509test`
2. In the "Capabilicy config" step, fill in:
    - Client Authentication: On
    - Select "Service accounts roles"

Enable the X509 authenticator:

3. Go to the "Credentials" tab
    - In "Client Authenticator", select "X509 Certificate".
    - Fill in Subject DN with the client certificate's subject name or pattern.

Make an HTTP request with the client certificate:

```console
$ http --cert certs/x509client.pem --cert-key certs/x509client-key.pem --verify certs/ca.pem --form POST https://keycloak.127-0-0-1.nip.io:8443/realms/master/protocol/openid-connect/token grant_type=client_credentials client_id=x509test
HTTP/1.1 200 OK
cache-control: no-store
content-length: 1412
content-type: application/json
date: Thu, 12 Sep 2024 16:43:42 GMT
pragma: no-cache
referrer-policy: no-referrer
server: envoy
strict-transport-security: max-age=31536000; includeSubDomains
x-content-type-options: nosniff
x-envoy-upstream-service-time: 12
x-frame-options: SAMEORIGIN
x-xss-protection: 1; mode=block

{
    "access_token": "<token removed from printout for brevity>",
    "expires_in": 60,
    "not-before-policy": 0,
    "refresh_expires_in": 0,
    "scope": "email profile",
    "token_type": "Bearer"
}
```
