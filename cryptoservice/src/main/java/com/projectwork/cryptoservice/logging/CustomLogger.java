package com.projectwork.cryptoservice.logging;

import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import org.slf4j.Logger;

public class ErrorLogger {

    /**
     * Loggt einen strukturierten Fehler auf WARN-Level.
     *
     * @param logger     der SLF4J Logger der aufrufenden Klasse
     * @param errorCode  das Fehlercode-Enum
     * @param message    optionaler Kontext zur Exception
     * @param exception  die ausgelöste Exception (z. B. ValidationException)
     */
    public static void logWarn(Logger logger, ErrorCode errorCode, String message, Exception exception) {
        logger.warn("[{}] {}: {}",
                errorCode.getCode(),
                errorCode.getMessage(),
                message != null ? message : exception.getMessage());
    }

    /**
     * Loggt einen strukturierten Fehler auf ERROR-Level mit Stacktrace.
     *
     * @param logger     der SLF4J Logger der aufrufenden Klasse
     * @param errorCode  das Fehlercode-Enum
     * @param message    optionaler Kontext zur Exception
     * @param exception  die ausgelöste Exception (z. B. ValidationException)
     */
    public static void logError(Logger logger, ErrorCode errorCode, String message, Exception exception) {
        logger.error("[{}] {}: {}", errorCode.getCode(), errorCode.getMessage(), message, exception);
    }
}
