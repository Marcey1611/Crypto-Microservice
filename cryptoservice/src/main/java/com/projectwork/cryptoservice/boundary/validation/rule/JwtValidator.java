package com.projectwork.cryptoservice.boundary.validation.rule;

import com.projectwork.cryptoservice.boundary.validation.FieldName;
import com.projectwork.cryptoservice.boundary.validation.cache.ReplayCache;
import com.projectwork.cryptoservice.businesslogic.jwtmanagement.JwtConsts;
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
 * SCPs:
 * - [6] All validation failures should result in input rejection
 * - [121] Log all input validation failures
 */
@Component
@RequiredArgsConstructor
public class JwtValidator {

    private static final Pattern JWT_PATTERN = Pattern.compile("^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$");

    private final ErrorHandler errorHandler;
    private final ReplayCache replayCache;


    /**
     * Validates the format of a JWT.
     *
     * @param jwt the JWT to validate
     * @throws BadRequestException if the JWT does not match the expected pattern
     */
    public final void validateJwtPattern(final String jwt) {
        final Matcher matcher = JWT_PATTERN.matcher(jwt);
        if (!matcher.matches()) {
            throw this.errorHandler.handleAuthError(ErrorCode.INVALID_JWT, "While validating JWT pattern.");
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
            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .setAllowedClockSkewSeconds(JwtConsts.CLOCK_SKEW_SECONDS)
                    .build()
                    .parseClaimsJws(jwt);
        } catch (final JwtException exception) {
            throw this.errorHandler.handleAuthError(ErrorCode.INVALID_JWT, "While validating JWT signature.");

        }
    }

    /**
     * Validates the expiration date of a JWT.
     *
     * @param claims the claims extracted from the JWT
     * @throws BadRequestException if the expiration date is null or in the past
     */
    public final void validateExpiration(final Claims claims) {
        if (null == claims.getExpiration() || claims.getExpiration().before(new Date())) {
            throw this.errorHandler.handleAuthError(ErrorCode.EXPIRED_JWT, "While validating JWT expiration date.");
        }
    }

    /**
     * Validates the issuer and audience of a JWT.
     *
     * @param claims the claims extracted from the JWT
     */
    public final void validateIssuerAndAudience(final Claims claims) {
        final String iss = claims.getIssuer();
        final String aud = claims.getAudience();
        if (!JwtConsts.ISSUER.equals(iss) || !JwtConsts.AUDIENCE.equals(aud)) {
            throw this.errorHandler.handleAuthError(ErrorCode.INVALID_JWT, "Invalid iss/aud in JWT.");
        }
    }

    /**
     * Validates and consumes the JWT ID (jti) to prevent replay attacks.
     *
     * @param claims the claims extracted from the JWT
     */
    public final void validateAndConsumeJti(final Claims claims) {
        final String jti = claims.getId();
        if (jti == null || jti.isBlank()) {
            throw this.errorHandler.handleAuthError(ErrorCode.INVALID_JWT, "Missing jti in JWT.");
        }
        final Date exp = claims.getExpiration();
        if (exp != null) {
            replayCache.register(jti, exp.toInstant().getEpochSecond());
        }
        if (!replayCache.consumeOnce(jti)) {
            throw this.errorHandler.handleForbiddenError(ErrorCode.INVALID_JWT, "JWT replay detected.");
        }
    }

    /**
     * Validates the algorithm specified in the JWT header.
     *
     * @param algorithm The algorithm string to validate.
     * @throws BadRequestException if the algorithm is invalid or insecure.
     */
    public final void validateAlgorithmFromHeader(final String algorithm) {
        if ("none".equalsIgnoreCase(algorithm)) {
            throw this.errorHandler.handleClientError(ErrorCode.INSECURE_JWT_ALGO, "While validating JWT algorithm from header.");
        }
    }
}
