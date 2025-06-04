package com.projectwork.cryptoservice.errorhandling.util;

import lombok.Getter;
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
    private final String code;
    private final String userMsg;
    private final String logHeadline;
    private final String context;
    private final Throwable exception;
    private final Level logLevel;
}
