package com.projectwork.cryptoservice.boundary.validation;

import java.util.Date;
import java.util.regex.Pattern;

import javax.crypto.SecretKey;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

public abstract class BaseValidator {

    private static final Pattern WHITELIST = Pattern.compile("^[a-zA-Z0-9 ._-]+$");
    private static final Pattern EXTENDED_WHITELIST = Pattern.compile("^[a-zA-Z0-9 .,;:!?@()\\[\\]{}\"'-]*$");
    private static final Pattern JWT_PATTERN = Pattern.compile("^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$");

    protected void checkNotBlank(final String field, final String fieldName) {
        if (field == null || field.isBlank()) {
            // TODO error handling
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
    }

    protected void checkMaxLength(final String field, final int maxLength, final String fieldName) {
        if (field.length() > maxLength) {
            // TODO error handling
            throw new IllegalArgumentException(fieldName + " is too long (max " + maxLength + " chars)");
        }
    }

    protected void checkNoUnicodeEscapes(final String field, final String fieldName) {
        if (field.contains("\\u")) {
            // TODO error handling
            throw new IllegalArgumentException(fieldName + " contains forbidden unicode escape sequences");
        }
    }

    protected void checkExtendedWhitelist(final String field, final String fieldName) {
        if (!EXTENDED_WHITELIST.matcher(field).matches()) {
            // TODO error handling
            throw new IllegalArgumentException(fieldName + " contains illegal characters");
        }
    }

    protected void checkWhitelist(final String field, final String fieldName) {
        if (!WHITELIST.matcher(field).matches()) {
            // TODO error handling
            throw new IllegalArgumentException(fieldName + " contains illegal characters");
        }
    }

    protected void checkJwt(final String jwt, final SecretKey jwtSigningKey) {
        if (!JWT_PATTERN.matcher(jwt).matches()) {
            // TODO error handling
            throw new IllegalArgumentException("JWT structure is invalid");
        }

        try {
            final Jws<Claims> parsedJwt = Jwts.parserBuilder()
                    .setSigningKey(jwtSigningKey)
                    .build()
                    .parseClaimsJws(jwt);

            final Claims claims = parsedJwt.getBody();

            final Date exp = claims.getExpiration();
            if (exp == null || exp.before(new Date())) {
                // TODO error handling
                throw new IllegalArgumentException("JWT expired");
            }

            final String keyAlias = claims.get("keyAlias", String.class);
            checkNotBlank(keyAlias, "keyAlias in jwt");
            checkMaxLength(keyAlias, 64, "keyAlias in jwt");
            checkNoUnicodeEscapes(keyAlias, "keyAlias in jwt");
            checkWhitelist(keyAlias, "keyAlias in jwt");

            final String algorithm = parsedJwt.getHeader().getAlgorithm();
            checkNotBlank(algorithm, "algorithm in jwt");
            checkMaxLength(algorithm, 64, "algorithm in jwt");
            checkNoUnicodeEscapes(algorithm, "algorithm in jwt");
            checkWhitelist(algorithm, "algorithm in jwt");
            if ("none".equalsIgnoreCase(algorithm)) {
                // TODO error handling
                throw new IllegalArgumentException("Insecure JWT algorithm 'none' is not allowed");
            }

        } catch (final JwtException exception) {
            // TODO error handling
            throw new IllegalArgumentException("Invalid JWT: " + exception.getMessage(), exception);
        }
    }
}

