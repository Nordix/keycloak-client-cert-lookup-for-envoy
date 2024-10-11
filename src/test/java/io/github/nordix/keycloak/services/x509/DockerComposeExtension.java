/**
 * Copyright (c) 2024 OpenInfra Foundation Europe and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License, Version 2.0
 * which accompanies this distribution, and is available at
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package io.github.nordix.keycloak.services.x509;

import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.nio.file.Path;

import org.jboss.logging.Logger;
import org.junit.jupiter.api.extension.AfterAllCallback;

public class DockerComposeExtension implements BeforeAllCallback, AfterAllCallback {

    private static final String DOCKER_COMPOSE_UP = "docker compose up --force-recreate --detach";
    private static final String DOCKER_COMPOSE_DOWN = "docker compose down";

    private static Logger logger = Logger.getLogger(DockerComposeExtension.class);

    private final String basePath;

    DockerComposeExtension(String basePath) {
        this.basePath = basePath;
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        run(DOCKER_COMPOSE_UP, "Failed to start Docker Compose.");
        logger.info("Use the following command to see the logs \"docker compose logs -f\"");
    }

    @Override
    public void afterAll(ExtensionContext context) throws Exception {
        run(DOCKER_COMPOSE_DOWN, "Failed to stop Docker Compose.");
    }

    private void run(String command, String errorMessage) throws Exception {
        ProcessBuilder processBuilder = new ProcessBuilder(command.split(" "));
        processBuilder.inheritIO();
        processBuilder.directory(Path.of(basePath).toFile());

        logger.infov("Running command \"{0}\" in directory \"{1}\"", command, processBuilder.directory());
        Process process = processBuilder.start();
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new IllegalStateException(errorMessage + " Exit code: " + exitCode);
        }
    }
}
