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

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.x509.X509ClientCertificateLookup;
import org.keycloak.services.x509.X509ClientCertificateLookupFactory;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;


/**
 * Factory for creating EnvoyProxySslClientCertificateLookup instances.
 */
public class EnvoyProxySslClientCertificateLookupFactory implements X509ClientCertificateLookupFactory {

    private final static String PROVIDER = "envoy";

    private List<List<X500Principal>> validCertPaths;

    @Override
    public void init(Scope config) {
        String pathsJson = config.get("cert-paths");
        if (pathsJson != null) {
            ObjectMapper mapper = new ObjectMapper();
            SimpleModule module = new SimpleModule();
            module.addDeserializer(X500Principal.class, new X500PrincipalDeserializer());
            mapper.registerModule(module);

            try {
                validCertPaths = mapper.readValue(pathsJson, new TypeReference<List<List<X500Principal>>>() {});
            } catch (Exception e) {
                throw new RuntimeException("Failed to parse cert-paths", e);
            }

        }
    }

    @Override
    public X509ClientCertificateLookup create(KeycloakSession session) {
        return new EnvoyProxySslClientCertificateLookup(validCertPaths);
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

    public class X500PrincipalDeserializer extends JsonDeserializer<X500Principal> {
        @Override
        public X500Principal deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JsonProcessingException {
            return new X500Principal(p.getValueAsString());
        }
    }
}
