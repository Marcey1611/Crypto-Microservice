package com.projectwork.cryptoservice.errorhandling.util;

import org.slf4j.event.Level;

public class ErrorDetailBuilder {
    private final String code;
    private String userMsg;
    private String logHeadline;
    private String context;
    private Throwable exception;
    private Level logLevel;

    public ErrorDetailBuilder(final ErrorCode errorCode) {
        this.code = errorCode.getCode();
        this.userMsg = errorCode.getUserMsg();
        this.logHeadline = errorCode.getLogHeadline();
        this.logLevel = errorCode.getLogLevel();
    }

    public ErrorDetailBuilder withUserMsg(final String userMsg) {
        this.userMsg = userMsg;
        return this;
    }

    public ErrorDetailBuilder withUserMsgFormatted(final Object... args) {
        this.userMsg = String.format(userMsg, args);
        return this;
    }

    public ErrorDetailBuilder withLogMsg(final String logMessage) {
        this.logHeadline = logMessage;
        return this;
    }

    public ErrorDetailBuilder withContext(final String context) {
        this.context = context;
        return this;
    }

    public ErrorDetailBuilder withException(final Throwable exception) {
        this.exception = exception;
        return this;
    }

    public ErrorDetailBuilder withLogMsgFormatted(final Object... args) {
        this.logHeadline = String.format(logHeadline, args);
        return this;
    }

    public ErrorDetailBuilder withLogLevel(final Level level) {
        this.logLevel = level;
        return this;
    }

    public ErrorDetail build() {
        return new ErrorDetail(code, userMsg, logHeadline, context, exception, logLevel);
    }
}
