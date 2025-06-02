package com.projectwork.cryptoservice.boundary.validation;

import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.SecretKey;

import com.projectwork.cryptoservice.errorhandling.exceptions.BadRequestException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;

import com.projectwork.cryptoservice.errorhandling.util.ErrorDetail;
import com.projectwork.cryptoservice.errorhandling.util.ErrorDetailBuilder;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


//TODO Validation neu ählich wie in chatgpt chat mit validation service logik: https://chatgpt.com/c/683dea7b-f760-800a-9584-b219a839787f

/**
 * Base class for validators that provides common validation methods.
 * It includes checks for blank fields, maximum length, character whitelisting,
 * and JWT validation.
 */
@RequiredArgsConstructor
public abstract class BaseValidator {

    private static final Logger LOGGER = LoggerFactory.getLogger(BaseValidator.class);

    private static final Pattern WHITELIST = Pattern.compile("^[a-zA-Z0-9 ._-]+$");
    private static final Pattern EXTENDED_WHITELIST = Pattern.compile("^[a-zA-Z0-9 .,;:!?@()\\[\\]{}\"'-]*$");
    static final Pattern JWT_PATTERN = Pattern.compile("^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$");
    private static final int MAX_LENGTH = 64;

    /**
     * Checks if the provided field is not blank.
     *
     * @param field     the field to check
     * @param fieldName the name of the field for error reporting
     * @throws BadRequestException if the field is blank
     */
    protected final void validateNotBlank(final String field, final String fieldName) {
        if (null == field || field.isBlank()) {
            final ErrorCode errorCode = ErrorCode.FIELD_BLANK;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withUserMsgFormatted(fieldName);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new BadRequestException(errorDetail);
        }
    }

    /**
     * Checks if the provided field exceeds the maximum length.
     *
     * @param field      the field to check
     * @param maxLength  the maximum allowed length
     * @param fieldName  the name of the field for error reporting
     * @throws BadRequestException if the field exceeds the maximum length
     */
    protected final void validateMaxLength(final String field, final int maxLength, final String fieldName) {
        if (field.length() > maxLength) {
            final ErrorCode errorCode = ErrorCode.FIELD_TOO_LONG;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withUserMsgFormatted(fieldName);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new BadRequestException(errorDetail);
        }
    }

    /**
     * Checks if the provided field contains Unicode escape sequences.
     *
     * @param field     the field to check
     * @param fieldName the name of the field for error reporting
     * @throws BadRequestException if the field contains Unicode escape sequences
     */
    protected final void validateNoUnicodeEscapes(final String field, final String fieldName) {
        if (field.contains("\\u")) {
            final ErrorCode errorCode = ErrorCode.INVALID_ENCODING;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withUserMsgFormatted(fieldName);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new BadRequestException(errorDetail);
        }
    }

    /**
     * Checks if the provided field matches the extended whitelist pattern.
     *
     * @param field     the field to check
     * @param fieldName the name of the field for error reporting
     * @throws BadRequestException if the field contains illegal characters
     */
    protected final void validateExtendedWhitelist(final String field, final String fieldName) {
        final Matcher matcher = EXTENDED_WHITELIST.matcher(field);
        if (!matcher.matches()) {
            final ErrorCode errorCode = ErrorCode.ILLEGAL_CHARS;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withUserMsgFormatted(fieldName);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new BadRequestException(errorDetail);
        }
    }

    /**
     * Checks if the provided field matches the standard whitelist pattern.
     *
     * @param field     the field to check
     * @param fieldName the name of the field for error reporting
     * @throws BadRequestException if the field contains illegal characters
     */
    protected final void validateWhitelist(final String field, final String fieldName) {
        final Matcher matcher = WHITELIST.matcher(field);
        if (!matcher.matches()) {
            final ErrorCode errorCode = ErrorCode.ILLEGAL_CHARS;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withUserMsgFormatted(fieldName);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new BadRequestException(errorDetail);
        }
    }

    /**
     * Validates a JWT token against the provided signing key.
     *
     * @param jwt             the JWT token to validate
     * @param jwtSigningKey   the secret key used to sign the JWT
     * @throws BadRequestException if the JWT is invalid, expired, or has an insecure algorithm
     */
    protected final void validateJwt(final String jwt, final SecretKey jwtSigningKey) {
        this.validateJwtPattern(jwt);
        final Jws<Claims> parsedJwt = this.validateJwtSignature(jwt, jwtSigningKey);
        final Claims claims = parsedJwt.getBody();

        final Date expiration = claims.getExpiration();
        this.validateJwtExpiration(expiration);

        final String jwtKeyAlias = claims.get("keyAlias", String.class);
        this.validateJwtKeyAlias(jwtKeyAlias);

        final String jwtAlgorithm = claims.get("algorithm", String.class);
        this.validateJwtAlgorithm(jwtAlgorithm);
    }

    /**
     * Validates the key alias in the JWT claims.
     *
     * @param keyAlias the key alias to validate
     * @throws BadRequestException if the key alias is invalid
     */
    private void validateJwtKeyAlias(final String keyAlias) {
        this.validateNotBlank(keyAlias, "keyAlias");
        this.validateMaxLength(keyAlias, MAX_LENGTH, "keyAlias");
        this.validateNoUnicodeEscapes(keyAlias, "keyAlias");
        this.validateWhitelist(keyAlias, "keyAlias");
    }

    /**
     * Validates the algorithm used in the JWT claims.
     *
     * @param algorithm the algorithm to validate
     * @throws BadRequestException if the algorithm is insecure or invalid
     */
    private void validateJwtAlgorithm(final String algorithm) {
        this.validateNotBlank(algorithm, "algorithm in jwt");
        this.validateMaxLength(algorithm, MAX_LENGTH, "algorithm in jwt");
        this.validateNoUnicodeEscapes(algorithm, "algorithm in jwt");
        this.validateWhitelist(algorithm, "algorithm in jwt");
        if ("none".equalsIgnoreCase(algorithm)) {
            final ErrorCode errorCode = ErrorCode.INSECURE_JWT_ALGO;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new BadRequestException(errorDetail);
        }
    }

    /**
     * Validates the format of a JWT token.
     *
     * @param jwt the JWT token to validate
     * @throws BadRequestException if the JWT format is invalid
     */
    private void validateJwtPattern(final String jwt) {
        final Matcher matcher = JWT_PATTERN.matcher(jwt);
        if (!matcher.matches()) {
            final ErrorCode errorCode = ErrorCode.INVALID_JWT;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new BadRequestException(errorDetail);
        }
    }

    /**
     * Parses and validates the signature of a JWT token.
     *
     * @param jwt             the JWT token to parse
     * @param jwtSigningKey   the secret key used to sign the JWT
     * @return the parsed JWT claims
     * @throws BadRequestException if the JWT signature is invalid
     */
    private Jws<Claims> validateJwtSignature(final String jwt, final SecretKey jwtSigningKey) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(jwtSigningKey)
                    .build()
                    .parseClaimsJws(jwt);
        } catch (final JwtException exception) {
            final ErrorCode errorCode = ErrorCode.INVALID_JWT;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new BadRequestException(errorDetail);
        }
    }

    /**
     * Checks if the JWT expiration date is valid.
     *
     * @param exp the expiration date of the JWT
     * @throws BadRequestException if the JWT is expired or has no expiration date
     */
    private void validateJwtExpiration(final Date exp) {
        if (null == exp || exp.before(new Date())) {
            final ErrorCode errorCode = ErrorCode.EXPIRED_JWT;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new BadRequestException(errorDetail);
        }
    }
}

