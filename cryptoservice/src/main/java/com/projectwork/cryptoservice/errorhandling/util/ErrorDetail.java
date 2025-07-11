package com.projectwork.cryptoservice.errorhandling.util;

import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

import lombok.RequiredArgsConstructor;

/**
 * ErrorDetail class that represents the details of an error.
 * It contains information such as error code, user message, log headline,
 * context, exception, and log level.
 */
@Getter
@RequiredArgsConstructor
public class ErrorDetail {

    private static final Logger LOGGER = LoggerFactory.getLogger(ErrorDetail.class);

    private final String code;
    private final String userMsg;
    private final String logHeadline;
    private final String context;
    private final Throwable exception;
    private final Level logLevel;

    public final void logError() {
        LOGGER.error("[{}] {}. {}", this.code, this.logHeadline, this.context);
    }

    public final void logErrorWithException() {
        final String message = this.exception.getMessage();
        LOGGER.error("[{}] {}. {}: {}", this.code, this.logHeadline, this.context, message, this.exception);
    }
}

