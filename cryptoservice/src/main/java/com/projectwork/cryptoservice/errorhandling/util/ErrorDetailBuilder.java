package com.projectwork.cryptoservice.errorhandling.util;

import org.slf4j.event.Level;

/**
 * Builder class for constructing ErrorDetail objects.
 * It allows setting various properties such as user message, log message, context, exception, and log level.
 */
public class ErrorDetailBuilder {

    private final String code;
    private String userMsg;
    private String logHeadline;
    private String context;
    private Throwable exception;
    private Level logLevel;

    /**
     * Constructor that initializes the ErrorDetailBuilder with an ErrorCode.
     * It sets the code, user message, log headline, and log level based on the provided ErrorCode.
     *
     * @param errorCode the ErrorCode to initialize the builder with
     */
    public ErrorDetailBuilder(final ErrorCode errorCode) {
        this.code = errorCode.getCode();
        this.userMsg = errorCode.getUserMsg();
        this.logHeadline = errorCode.getLogHeadline();
        this.logLevel = errorCode.getLogLevel();
    }

    /**
     * Constructor that initializes the ErrorDetailBuilder with an ErrorDetail.
     * It sets the code, user message, log headline, context, exception, and log level based on the provided ErrorDetail.
     *
     * @param args the ErrorDetail to initialize the builder with
     */
    public final void withUserMsgFormatted(final Object... args) {
        this.userMsg = String.format(this.userMsg, args);
    }

    /**
     * Sets the context for the error detail.
     *
     * @param context the user message to set
     * @return the current ErrorDetailBuilder instance
     */
    public final ErrorDetailBuilder withContext(final String context) {
        this.context = context;
        return this;
    }

    /**
     * Sets the exception for the error detail.
     *
     * @param exception the log headline to set
     * @return the current ErrorDetailBuilder instance
     */
    public final ErrorDetailBuilder withException(final Throwable exception) {
        this.exception = exception;
        return this;
    }

    /**
     * Sets the log message formatted for the error detail.
     *
     * @param args the log level to set
     */
    public final void withLogMsgFormatted(final Object... args) {
        this.logHeadline = String.format(this.logHeadline, args);
    }

    /**
     * builds the ErrorDetail object with the current properties set in the builder.
     *
     * @return the current ErrorDetailBuilder instance
     */
    public final ErrorDetail build() {
        return new ErrorDetail(this.code, this.userMsg, this.logHeadline, this.context, this.exception, this.logLevel);
    }
}
