package com.projectwork.cryptoservice.boundary.validation;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;

/**
 * ValidationService class that provides methods for validating text inputs and JWT tokens.
 * It uses various validators to ensure the integrity and correctness of the data.
 */
@Service
@RequiredArgsConstructor
public class ValidationService {

    private final FieldValidator fieldValidator;
    private final EncodingValidator encodingValidator;
    private final JwtValidator jwtValidator;
    private final JwtClaimsValidator jwtClaimsValidator;

    /**
     * Validates a text input against several criteria including not being blank,
     * having a maximum length, and not containing Unicode escapes.
     * Optionally validates against an extended whitelist.
     *
     * @param text       the text to validate
     * @param name       the name of the field for error reporting
     * @param maxLength  the maximum allowed length of the text
     * @param extended   whether to use an extended whitelist for validation
     */
    public final void validateText(final String text, final String name, final int maxLength, final boolean extended) {
        this.fieldValidator.validateNotBlank(text, name);
        this.fieldValidator.validateMaxLength(text, maxLength, name);
        this.encodingValidator.validateNoUnicodeEscapes(text, name);
        if (extended) {
            this.fieldValidator.validateExtendedWhitelist(text, name);
        } else {
            this.fieldValidator.validateWhitelist(text, name);
        }
    }

    /**
     * Validates a text input without using a whitelist.
     * Checks that the text is not blank, does not exceed the maximum length,
     * and does not contain Unicode escapes.
     *
     * @param text      the text to validate
     * @param name      the name of the field for error reporting
     * @param maxLength the maximum allowed length of the text
     */
    public void validateTextWithoutWhitelist(final String text, final String name, final int maxLength) {
        this.fieldValidator.validateNotBlank(text, name);
        this.fieldValidator.validateMaxLength(text, maxLength, name);
        this.encodingValidator.validateNoUnicodeEscapes(text, name);
    }

    /**
     * Validates a JWT token against its pattern, signature, expiration, key alias, and algorithm.
     *
     * @param jwt the JWT token to validate
     * @param key the secret key used for signature validation
     */
    public final void validateJwt(final String jwt, final SecretKey key) {
        this.jwtValidator.validateJwtPattern(jwt);
        final Jws<Claims> parsed = this.jwtValidator.validateSignature(jwt, key);
        final Claims claims = parsed.getBody();
        final JwsHeader<?> header = (JwsHeader<?>) parsed.getHeader();

        final Date expiration = claims.getExpiration();
        this.jwtValidator.validateExpiration(expiration);
        final String keyAlias = claims.get("keyAlias", String.class);
        this.jwtClaimsValidator.validateKeyAlias(keyAlias);
        final String algorithm = header.getAlgorithm();
        this.jwtClaimsValidator.validateAlgorithmFromHeader(algorithm);
    }
}
