/**
 * Copyright (c) 2024 OpenInfra Foundation Europe and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License, Version 2.0
 * which accompanies this distribution, and is available at
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package io.github.nordix.keycloak.services.x509;

import java.security.cert.X509Certificate;

import org.keycloak.http.FormPartValue;
import org.keycloak.http.HttpRequest;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.UriInfo;

/**
 * Minimal implementation of Keycloak's HttpRequest for unit testing purposes.
 */
public class HttpRequestImpl implements HttpRequest {

    private org.jboss.resteasy.spi.HttpRequest delegate;

    public HttpRequestImpl(org.jboss.resteasy.spi.HttpRequest delegate) {
        this.delegate = delegate;
    }

    @Override
    public HttpHeaders getHttpHeaders() {
        return delegate.getHttpHeaders();
    }

    @Override
    public String getHttpMethod() {
        throw new UnsupportedOperationException("Unimplemented method 'getHttpMethod'");
    }

    @Override
    public MultivaluedMap<String, String> getDecodedFormParameters() {
        throw new UnsupportedOperationException("Unimplemented method 'getDecodedFormParameters'");
    }

    @Override
    public MultivaluedMap<String, FormPartValue> getMultiPartFormParameters() {
        throw new UnsupportedOperationException("Unimplemented method 'getMultiPartFormParameters'");
    }

    @Override
    public X509Certificate[] getClientCertificateChain() {
        throw new UnsupportedOperationException("Unimplemented method 'getClientCertificateChain'");
    }

    @Override
    public UriInfo getUri() {
        throw new UnsupportedOperationException("Unimplemented method 'getUri'");
    }

}
