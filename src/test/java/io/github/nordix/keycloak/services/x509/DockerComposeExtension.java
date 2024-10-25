/**
 * Copyright (c) 2024 OpenInfra Foundation Europe and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License, Version 2.0
 * which accompanies this distribution, and is available at
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package io.github.nordix.keycloak.services.x509;

import java.io.File;

import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import org.apache.commons.exec.ExecuteException;
import org.apache.commons.exec.ExecuteResultHandler;
import org.jboss.logging.Logger;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * JUnit extension for starting and stopping Docker Compose.
 */
public class DockerComposeExtension implements BeforeAllCallback, AfterAllCallback {

    private static final String DOCKER_COMPOSE_UP = "docker compose up --force-recreate --no-color --abort-on-container-exit";
    private static final String DOCKER_COMPOSE_DOWN = "docker compose down";

    private static Logger logger = Logger.getLogger(DockerComposeExtension.class);

    private final String basePath;

    DockerComposeExtension(String basePath) {
        this.basePath = basePath;
    }

    /**
     * Start Docker Compose before all tests but do not wait for it to complete.
     * That allows the logs to be displayed in the console in parallel with the test execution.
     */
    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        run(DOCKER_COMPOSE_UP, false, "Failed to start Docker Compose.");
    }

    /**
     * Stop Docker Compose after all tests.
     */
    @Override
    public void afterAll(ExtensionContext context) throws Exception {
        run(DOCKER_COMPOSE_DOWN, true, "Failed to stop Docker Compose.");
    }

    /**
     * Run a command on a subprocess.
     *
     * Note:
     * Use apache-commons-exec since ProcessBuilder had problems with output redirection
     * (output stopped in the middle even if the process was still running).
     */
    private void run(String command, boolean waitForCompletion, String errorMessage) throws Exception {
        CommandLine cmdLine = CommandLine.parse(command);
        DefaultExecutor executor = DefaultExecutor.builder().setWorkingDirectory(new File(basePath)).get();

        logger.infov("Running command \"{0}\" in directory \"{1}\"", command, executor.getWorkingDirectory());

        if (waitForCompletion) {
            int exitValue = executor.execute(cmdLine);
            if (exitValue != 0) {
                throw new Exception(errorMessage);
            }
        } else {
            executor.execute(cmdLine, new ExecuteResultHandler() {
                @Override
                public void onProcessComplete(int exitValue) {
                    if (exitValue != 0) {
                        logger.error(errorMessage);
                    }
                }

                @Override
                public void onProcessFailed(ExecuteException e) {
                    logger.error(errorMessage, e);
                }
            });
        }
    }
}
