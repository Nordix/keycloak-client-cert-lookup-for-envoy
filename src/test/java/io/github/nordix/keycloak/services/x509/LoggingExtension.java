package io.github.nordix.keycloak.services.x509;

import java.util.Optional;

import org.jboss.logging.Logger;
import org.junit.jupiter.api.extension.BeforeTestExecutionCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestWatcher;

public class LoggingExtension implements TestWatcher, BeforeTestExecutionCallback {

    private static Logger logger = Logger.getLogger(LoggingExtension.class);

    @Override
    public void testDisabled(ExtensionContext context, Optional<String> reason) {
        logger.warnv("Test {0} is disabled: {11}", context.getDisplayName(), reason.orElse("No reason provided"));
    }

    @Override
    public void testSuccessful(ExtensionContext context) {
        logger.infov("Test {0} succeeded", context.getDisplayName());
    }

    @Override
    public void testAborted(ExtensionContext context, Throwable cause) {
        logger.errorv(cause, "Test {0} aborted", context.getDisplayName());
    }

    @Override
    public void testFailed(ExtensionContext context, Throwable cause) {
        logger.errorv(cause, "Test {0} failed", context.getDisplayName());
    }

    @Override
    public void beforeTestExecution(ExtensionContext context) throws Exception {
        logger.infov("Starting test {0}", context.getDisplayName());
    }

}
