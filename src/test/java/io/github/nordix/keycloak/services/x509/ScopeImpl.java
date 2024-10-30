/**
 * Copyright (c) 2024 OpenInfra Foundation Europe and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License, Version 2.0
 * which accompanies this distribution, and is available at
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package io.github.nordix.keycloak.services.x509;

import java.util.Set;
import java.util.HashMap;
import java.util.Map;

import org.keycloak.Config.Scope;

/**
 * Minimal implementation of Keycloak's Scope for unit testing purposes.
 */
public class ScopeImpl implements Scope {

    private final Map<String, String> properties = new HashMap<>();

    /**
     * Create a new Scope instance from a list of key-value pairs.
     *
     * @param pairs A list of key-value pairs.
     * @return A new Scope instance.
     */
    public static Scope fromPairs(String... pairs) {
        ScopeImpl scope = new ScopeImpl();
        for (int i = 0; i < pairs.length; i += 2) {
            scope.put(pairs[i], pairs[i + 1]);
        }
        return scope;
    }

    ScopeImpl() {
    }

    void put(String key, String value) {
        properties.put(key, value);
    }

    @Override
    public String get(String key) {
        return properties.get(key);
    }

    @Override
    public String get(String key, String defaultValue) {
        return properties.getOrDefault(key, defaultValue);
    }

    @Override
    public String[] getArray(String key) {
        throw new UnsupportedOperationException("Unimplemented method 'getArray'");
    }

    @Override
    public Integer getInt(String key) {
        throw new UnsupportedOperationException("Unimplemented method 'getInt'");
    }

    @Override
    public Integer getInt(String key, Integer defaultValue) {
        String val = properties.get(key);
        return val != null ? Integer.parseInt(val) : defaultValue;
    }

    @Override
    public Long getLong(String key) {
        throw new UnsupportedOperationException("Unimplemented method 'getLong'");
    }

    @Override
    public Long getLong(String key, Long defaultValue) {
        throw new UnsupportedOperationException("Unimplemented method 'getLong'");
    }

    @Override
    public Boolean getBoolean(String key) {
        throw new UnsupportedOperationException("Unimplemented method 'getBoolean'");
    }

    @Override
    public Boolean getBoolean(String key, Boolean defaultValue) {
        throw new UnsupportedOperationException("Unimplemented method 'getBoolean'");
    }

    @Override
    public Scope scope(String... scope) {
        throw new UnsupportedOperationException("Unimplemented method 'scope'");
    }

    @Override
    public Set<String> getPropertyNames() {
        throw new UnsupportedOperationException("Unimplemented method 'getPropertyNames'");
    }
}
