/**
 * Copyright (c) 2024 OpenInfra Foundation Europe and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License, Version 2.0
 * which accompanies this distribution, and is available at
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package io.github.nordix.keycloak.services.x509;

import java.io.IOException;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.jboss.logging.Logger;
import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.x509.X509ClientCertificateLookup;
import org.keycloak.services.x509.X509ClientCertificateLookupFactory;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;

/**
 * Factory for creating EnvoyProxySslClientCertificateLookup instances.
 */
public class EnvoyProxySslClientCertificateLookupFactory implements X509ClientCertificateLookupFactory {

    private static Logger logger = Logger.getLogger(EnvoyProxySslClientCertificateLookupFactory.class);

    private static final String PROVIDER = "envoy";

    private List<List<X500Principal>> verifyCertPaths = null;

    @Override
    public void init(Scope config) {
        String pathsJson = config.get("cert-path-verify");
        if (pathsJson != null) {
            ObjectMapper mapper = new ObjectMapper();
            SimpleModule module = new SimpleModule();
            module.addDeserializer(X500Principal.class, new X500PrincipalDeserializer());
            mapper.registerModule(module);

            try {
                verifyCertPaths = mapper.readValue(pathsJson, new TypeReference<List<List<X500Principal>>>() {
                });
            } catch (Exception e) {
                throw new RuntimeException("Failed to parse cert-paths", e);
            }
        }
    }

    @Override
    public X509ClientCertificateLookup create(KeycloakSession session) {
        logger.debugv("Creating Envoy X509 client certificate lookup: certificate path verification {0} {1}",
                verifyCertPaths == null ? "disabled" : "enabled",
                verifyCertPaths == null ? "" : verifyCertPaths);
        return new EnvoyProxySslClientCertificateLookup(verifyCertPaths);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Intentionally left empty.
    }

    @Override
    public void close() {
        // Intentionally left empty.
    }

    @Override
    public String getId() {
        return PROVIDER;
    }

    public class X500PrincipalDeserializer extends JsonDeserializer<X500Principal> {
        @Override
        public X500Principal deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
            return new X500Principal(p.getValueAsString());
        }
    }
}
