package com.projectwork.cryptoservice.boundary.validation;

import java.util.Date;
import java.util.regex.Pattern;

import javax.crypto.SecretKey;

import com.projectwork.cryptoservice.errorhandling.exceptions.BadRequestException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;

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
            throw new BadRequestException(ErrorCode.FIELD_BLANK.formatMessage(fieldName));
        }
    }

    protected void checkMaxLength(final String field, final int maxLength, final String fieldName) {
        if (field.length() > maxLength) {
            throw new BadRequestException(ErrorCode.FIELD_TOO_LONG.formatMessage(fieldName));
        }
    }

    protected void checkNoUnicodeEscapes(final String field, final String fieldName) {
        if (field.contains("\\u")) {
            throw new BadRequestException(ErrorCode.INVALID_ENCODING.formatMessage(fieldName));
        }
    }

    protected void checkExtendedWhitelist(final String field, final String fieldName) {
        if (!EXTENDED_WHITELIST.matcher(field).matches()) {
            throw new BadRequestException(ErrorCode.ILLEGAL_CHARS.formatMessage(fieldName));
        }
    }

    protected void checkWhitelist(final String field, final String fieldName) {
        if (!WHITELIST.matcher(field).matches()) {
            throw new BadRequestException(ErrorCode.ILLEGAL_CHARS.formatMessage(fieldName));
        }
    }

    protected void checkJwt(final String jwt, final SecretKey jwtSigningKey) {
        if (!JWT_PATTERN.matcher(jwt).matches()) {
            throw new BadRequestException(ErrorCode.INVALID_JWT.defaultMessage());
        }

        try {
            final Jws<Claims> parsedJwt = Jwts.parserBuilder()
                    .setSigningKey(jwtSigningKey)
                    .build()
                    .parseClaimsJws(jwt);

            final Claims claims = parsedJwt.getBody();

            final Date exp = claims.getExpiration();
            if (exp == null || exp.before(new Date())) {
                throw new BadRequestException(ErrorCode.EXPIRED_JWT.defaultMessage());
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
                throw new BadRequestException(ErrorCode.INSECURE_JWT_ALGO.defaultMessage());
            }

        } catch (final JwtException exception) {
            throw new BadRequestException(ErrorCode.INVALID_JWT.defaultMessage());
        }
    }
}

