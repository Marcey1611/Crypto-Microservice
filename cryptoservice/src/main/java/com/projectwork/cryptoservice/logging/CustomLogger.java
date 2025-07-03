package com.projectwork.cryptoservice.logging;

import com.projectwork.cryptoservice.errorhandling.util.ErrorDetail;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class CustomLogger {

    private static final Logger LOGGER = LoggerFactory.getLogger(CustomLogger.class);

    public final void logError(final ErrorDetail errorDetail) {
        final String code = errorDetail.getCode();
        final String logHeadline = errorDetail.getLogHeadline();
        final Throwable exception = errorDetail.getException();
        final String message = exception.getMessage();
        LOGGER.error("[{}] {}: {}", code, logHeadline, message);
    }

    public final void logErrorWithException(final ErrorDetail errorDetail) {
        final String code = errorDetail.getCode();
        final String logHeadline = errorDetail.getLogHeadline();
        final Throwable exception = errorDetail.getException();
        final String message = exception.getMessage();
        LOGGER.error("[{}] {}: {}", code, logHeadline, message, exception);
    }
}
