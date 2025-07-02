package com.projectwork.cryptoservice.boundary.validation;

import com.projectwork.cryptoservice.errorhandling.exceptions.BadRequestException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorDetail;
import com.projectwork.cryptoservice.errorhandling.util.ErrorDetailBuilder;
import com.projectwork.cryptoservice.logging.CustomLogger;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * JwtValidator is a component that validates JWTs (JSON Web Tokens) for format, signature, and expiration.
 * It checks if the JWT matches the expected pattern, validates its signature using a provided secret key,
 * and ensures that the token has not expired.
 */
@Component
@RequiredArgsConstructor
public class JwtValidator {

    private final CustomLogger customLogger;

    private static final Pattern JWT_PATTERN = Pattern.compile("^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$");

    /**
     * Validates the format of a JWT.
     *
     * @param jwt the JWT to validate
     * @throws BadRequestException if the JWT does not match the expected pattern
     */
    public final void validateJwtPattern(final String jwt) {
        final Matcher matcher = JWT_PATTERN.matcher(jwt);
        if (!matcher.matches()) {
            final ErrorCode errorCode = ErrorCode.INVALID_JWT;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            this.customLogger.logValidationError(errorDetail);
            throw new BadRequestException(errorDetail);
        }
    }

    /**
     * Validates the JWT using the provided secret key.
     *
     * @param jwt the JWT to validate
     * @param key the secret key used for signature validation
     * @return the parsed JWT claims if validation is successful
     * @throws BadRequestException if the JWT signature is invalid
     */
    public final Jws<Claims> validateSignature(final String jwt, final SecretKey key) {
        try {
            final JwtParser build = Jwts.parserBuilder().setSigningKey(key).build();
            return build.parseClaimsJws(jwt);
        } catch (final JwtException exception) {
            final ErrorCode errorCode = ErrorCode.INVALID_JWT;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            this.customLogger.logValidationError(errorDetail);
            throw new BadRequestException(errorDetail);
        }
    }

    /**
     * Validates the expiration date of a JWT.
     *
     * @param expiration the expiration date to validate
     * @throws BadRequestException if the expiration date is null or in the past
     */
    public final void validateExpiration(final Date expiration) {
        if (null == expiration || expiration.before(new Date())) {
            final ErrorCode errorCode = ErrorCode.EXPIRED_JWT;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            this.customLogger.logValidationError(errorDetail);
            throw new BadRequestException(errorDetail);
        }
    }
}
