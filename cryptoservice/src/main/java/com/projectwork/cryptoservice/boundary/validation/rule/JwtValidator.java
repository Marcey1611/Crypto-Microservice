package com.projectwork.cryptoservice.boundary.validation.rule;

import com.projectwork.cryptoservice.boundary.validation.FieldName;
import com.projectwork.cryptoservice.errorhandling.exceptions.BadRequestException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorHandler;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
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

    private static final Pattern JWT_PATTERN = Pattern.compile("^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$");
    private static final int MAX_LENGTH = 64;

    private final ErrorHandler errorHandler;
    private final AsciiValidator asciiValidator;
    private final CharsetValidator charsetValidator;
    private final ControlCharValidator controlCharValidator;
    private final LengthValidator lengthValidator;
    private final NullOrBlankValidator nullOrBlankValidator;
    private final WhitelistValidator whitelistValidator;

    /**
     * Validates the format of a JWT.
     *
     * @param jwt the JWT to validate
     * @throws BadRequestException if the JWT does not match the expected pattern
     */
    public final void validateJwtPattern(final String jwt) {
        final Matcher matcher = JWT_PATTERN.matcher(jwt);
        if (!matcher.matches()) {
            throw this.errorHandler.handleError(ErrorCode.INVALID_JWT, "While validating JWT pattern.");
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
            throw this.errorHandler.handleError(ErrorCode.INVALID_JWT, "While validating JWT signature.");

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
            throw this.errorHandler.handleError(ErrorCode.EXPIRED_JWT, "While validating JWT expiration date.");
        }
    }

    /**
     * Validates the algorithm specified in the JWT header.
     *
     * @param algorithm The algorithm string to validate.
     * @throws BadRequestException if the algorithm is invalid or insecure.
     */
    public final void validateAlgorithmFromHeader(final String algorithm, final int maxLength) {
        this.nullOrBlankValidator.validateNullOrBlank(algorithm, FieldName.ALGORITHM_HEADER);
        this.lengthValidator.validateLength(algorithm, maxLength, FieldName.ALGORITHM_HEADER);
        this.asciiValidator.validateAscii(algorithm, FieldName.ALGORITHM_HEADER);
        this.charsetValidator.validateCharset(algorithm, FieldName.ALGORITHM_HEADER);
        this.controlCharValidator.validateControlChars(algorithm, FieldName.ALGORITHM_HEADER);
        this.whitelistValidator.validateWhitelist(algorithm, FieldName.ALGORITHM_HEADER, false);

        if ("none".equalsIgnoreCase(algorithm)) {
            throw this.errorHandler.handleError(ErrorCode.INSECURE_JWT_ALGO, "While validating JWT algorithm from header.");
        }
    }

    /**
     * Validates the key alias used in JWT operations.
     *
     * @param alias The key alias to validate.
     * @throws BadRequestException if the alias is blank, too long, contains Unicode escapes, or is not whitelisted.
     */
    public final void validateKeyAlias(final String alias, final int maxLength) {
        this.nullOrBlankValidator.validateNullOrBlank(alias, FieldName.KEY_ALIAS);
        this.lengthValidator.validateLength(alias, maxLength, FieldName.KEY_ALIAS);
        this.asciiValidator.validateAscii(alias, FieldName.KEY_ALIAS);
        this.charsetValidator.validateCharset(alias, FieldName.KEY_ALIAS);
        this.controlCharValidator.validateControlChars(alias, FieldName.KEY_ALIAS);
        this.whitelistValidator.validateWhitelist(alias, FieldName.KEY_ALIAS, false);
    }
}
