/**
 * Copyright (c) 2024 OpenInfra Foundation Europe and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License, Version 2.0
 * which accompanies this distribution, and is available at
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package io.github.nordix.keycloak.services.x509;

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.x509.X509ClientCertificateLookup;
import org.keycloak.services.x509.X509ClientCertificateLookupFactory;

/**
 * Factory for creating EnvoyProxySslClientCertificateLookup instances.
 */
public class EnvoyProxySslClientCertificateLookupFactory implements X509ClientCertificateLookupFactory {

    private final static String PROVIDER = "envoy";

    @Override
    public X509ClientCertificateLookup create(KeycloakSession session) {
        return new EnvoyProxySslClientCertificateLookup();
    }

    @Override
    public void init(Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER;
    }
}
