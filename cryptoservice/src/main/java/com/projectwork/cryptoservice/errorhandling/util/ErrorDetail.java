package com.projectwork.cryptoservice.errorhandling.util;

import org.slf4j.event.Level;

public class ErrorDetail {
    private final String code;
    private final String userMsg;
    private final String logMsg;
    private final Level logLevel;

    public ErrorDetail(final String code, final String userMsg, final String logMsg, final Level logLevel) {
        this.code = code;
        this.userMsg = userMsg;
        this.logMsg = logMsg;
        this.logLevel = logLevel;
    }

    public String getCode() {
        return code;
    }

    public String getUserMsg() {
        return userMsg;
    }

    public String getLogMsg() {
        return logMsg;
    }

    public Level getLogLevel() {
        return logLevel;
    }
}
