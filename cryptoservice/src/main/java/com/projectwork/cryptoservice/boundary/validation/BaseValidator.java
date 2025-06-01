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
            throw new BadRequestException(ErrorCode.FIELD_BLANK.builder()
                .withUserMsgFormatted(fieldName)
                .build()
            );
        }
    }

    protected void checkMaxLength(final String field, final int maxLength, final String fieldName) {
        if (field.length() > maxLength) {
            throw new BadRequestException(ErrorCode.FIELD_TOO_LONG.builder()
                .withUserMsgFormatted(fieldName)
                .build()
            );
        }
    }

    protected void checkNoUnicodeEscapes(final String field, final String fieldName) {
        if (field.contains("\\u")) {
            throw new BadRequestException(ErrorCode.INVALID_ENCODING.builder()
                .withUserMsgFormatted(fieldName)
                .build()
            );
        }
    }

    protected void checkExtendedWhitelist(final String field, final String fieldName) {
        if (!EXTENDED_WHITELIST.matcher(field).matches()) {
            throw new BadRequestException(ErrorCode.ILLEGAL_CHARS.builder()
                .withUserMsgFormatted(fieldName)
                .build()
            );
        }
    }

    protected void checkWhitelist(final String field, final String fieldName) {
        if (!WHITELIST.matcher(field).matches()) {
            throw new BadRequestException(ErrorCode.ILLEGAL_CHARS.builder()
                .withUserMsgFormatted(fieldName)
                .build()
            );
        }
    }

    protected void checkJwt(final String jwt, final SecretKey jwtSigningKey) {
        checkJwtPattern(jwt);
        final Jws<Claims> parsedJwt = checkJwtSignature(jwt, jwtSigningKey);
        final Claims claims = parsedJwt.getBody();
        checkJwtExpiration(claims.getExpiration());
        checkJwtKeyAlias(claims.get("keyAlias", String.class));
        checkJwtAlgorithm(parsedJwt.getHeader().getAlgorithm());
    }

    private void checkJwtPattern(final String jwt) {
        if (!JWT_PATTERN.matcher(jwt).matches()) {
            throw new BadRequestException(ErrorCode.INVALID_JWT.builder().build());
        }
    }

    private Jws<Claims> checkJwtSignature(final String jwt, final SecretKey jwtSigningKey) {
        try {
            return Jwts.parserBuilder()
                .setSigningKey(jwtSigningKey)
                .build()
                .parseClaimsJws(jwt);
        } catch (JwtException e) {
            throw new BadRequestException(ErrorCode.INVALID_JWT.builder().build());
        }
    }

    private void checkJwtExpiration(final Date exp) {
        if (exp == null || exp.before(new Date())) {
            throw new BadRequestException(ErrorCode.EXPIRED_JWT.builder().build());
        }
    }

    private void checkJwtKeyAlias(final String keyAlias) {
        checkNotBlank(keyAlias, "keyAlias");
        checkMaxLength(keyAlias, 64, "keyAlias");
        checkNoUnicodeEscapes(keyAlias, "keyAlias");
        checkWhitelist(keyAlias, "keyAlias");
    }

    private void checkJwtAlgorithm(final String algorithm) {
        checkNotBlank(algorithm, "algorithm in jwt");
        checkMaxLength(algorithm, 64, "algorithm in jwt");
        checkNoUnicodeEscapes(algorithm, "algorithm in jwt");
        checkWhitelist(algorithm, "algorithm in jwt");
        if ("none".equalsIgnoreCase(algorithm)) {
            throw new BadRequestException(ErrorCode.INSECURE_JWT_ALGO.builder().build());
        }
    }
}

