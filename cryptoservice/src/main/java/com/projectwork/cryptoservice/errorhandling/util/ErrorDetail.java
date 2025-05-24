package com.projectwork.cryptoservice.errorhandling.util;

import org.slf4j.event.Level;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class ErrorDetail {
    private final String code;
    private final String userMsg;
    private final String logHeadline;
    private final String context;
    private final Throwable exception;
    private final Level logLevel;

    public String getCode() {return code;}
    public String getUserMsg() {return userMsg;}
    public String getLogHeadline() {return logHeadline;}
    public String getContext() {return context;}
    public Throwable getException() {return exception;}
    public Level getLogLevel() {return logLevel;}
}
