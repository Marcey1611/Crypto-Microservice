package com.projectwork.cryptoservice.errorhandling.util;

import org.slf4j.event.Level;

public class ErrorDetailBuilder {
    private final String code;
    private String userMsg;
    private String logMsg;
    private Level logLevel;

    public ErrorDetailBuilder(final ErrorCode errorCode) {
        this.code = errorCode.getCode();
        this.userMsg = errorCode.getUserMsg();
        this.logMsg = errorCode.getLogMsg();
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
        this.logMsg = logMessage;
        return this;
    }

    public ErrorDetailBuilder withLogMsgFormatted(final Object... args) {
        this.logMsg = String.format(logMsg, args);
        return this;
    }

    public ErrorDetailBuilder withLogLevel(final Level level) {
        this.logLevel = level;
        return this;
    }

    public ErrorDetail build() {
        return new ErrorDetail(code, userMsg, logMsg, logLevel);
    }
}
