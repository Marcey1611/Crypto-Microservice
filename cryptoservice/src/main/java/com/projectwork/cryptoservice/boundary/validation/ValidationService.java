package com.projectwork.cryptoservice.boundary.validation;

import com.projectwork.cryptoservice.boundary.validation.rule.*;
import com.projectwork.cryptoservice.boundary.validation.rule.JwtValidator;
import com.projectwork.cryptoservice.businesslogic.keymanagement.KeyStoreHelper;
import com.projectwork.cryptoservice.entity.models.decrypt.DecryptRequest;
import com.projectwork.cryptoservice.entity.models.encrypt.EncryptRequest;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtRequest;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;

/**
 * ValidationService class that provides methods for validating JWT generation, encryption, and decryption requests.
 * It uses various validators to ensure the integrity and correctness of the data.
 * SCPs:
 * - [1] Conduct all data validation on a trusted system (e.g., The server)
 * - [2] Identify all data sources and classify them into trusted and untrusted. Validate all data from untrusted sources
 * - [3] There should be a centralized input validation routine for the application
 * - [4] Specify proper character sets, such as UTF-8, for all sources of input
 * - [6] All validation failures should result in input rejection
 * - [8] Validate all client-provided data before processing
 * - [13] Validate data length
 * - [14] Validate all input against a "white" list of allowed characters, whenever possible
 * - [112] Error handling logic associated with security controls should deny access by default
 */
@Service
@RequiredArgsConstructor
public class ValidationService {

    private static final int ISSUED_TO_MAX_LENGTH = 64;
    private static final int CLIENT_NAME_MAX_LENGTH = 64;
    private static final int PLAIN_TEXT_MAX_LENGTH = 2048;
    private static final int CIPHER_TEXT_MAX_LENGTH = 2048;
    private static final int JWT_MAX_LENGTH = 4096;
    private static final int JWT_ALGORITHM_MAX_LENGTH = 64;
    private static final int JWT_KEY_ALIAS_MAX_LENGTH = 64;

    private final KeyStoreHelper keyStoreHelper;
    private final AsciiValidator asciiValidator;
    private final CharsetValidator charsetValidator;
    private final ControlCharValidator controlCharValidator;
    private final LengthValidator lengthValidator;
    private final NullOrBlankValidator nullOrBlankValidator;
    private final WhitelistValidator whitelistValidator;
    private final JwtValidator jwtValidator;
    private final Base64Validator base64Validator;

    @Value("${master.keystore.path}")
    private String masterKeystorePath;

    @Value("${master.keystore.password}")
    private String masterKeystorePassword;

    /**
     * Validates the GenerateKeyRequest for key generation.
     *
     * @param clientName the name of the client making the request
     */
    public final void validateGenerateKeyRequest(final String clientName) {
        this.validateClientName(clientName);
    }

    /**
     * Validates the GenerateJwtRequest for JWT generation.
     *
     * @param generateJwtRequest the GenerateJwtRequest containing the parameters for JWT generation
     * @param clientName   the name of the client making the request
     */
    public final void validateGenerateJwtRequest(final GenerateJwtRequest generateJwtRequest, final String clientName) {
        this.validateClientName(clientName);
        final String issuedTo = generateJwtRequest.getIssuedTo();

        this.nullOrBlankValidator.validateNullOrBlank(issuedTo, FieldName.ISSUED_TO);
        this.lengthValidator.validateLength(issuedTo, ISSUED_TO_MAX_LENGTH, FieldName.ISSUED_TO);
        this.asciiValidator.validateAscii(issuedTo, FieldName.ISSUED_TO);
        this.charsetValidator.validateCharset(issuedTo, FieldName.ISSUED_TO);
        this.controlCharValidator.validateControlChars(issuedTo, FieldName.ISSUED_TO);
        this.whitelistValidator.validateWhitelist(issuedTo, FieldName.ISSUED_TO, false);
    }

    /**
     * Validates the EncryptRequest for encryption.
     *
     * @param encryptRequest the EncryptRequest containing the plain text and JWT
     * @param clientName   the name of the client making the request
     */
    public final void validateEncryptRequest(final EncryptRequest encryptRequest, final String clientName) {
        this.validateClientName(clientName);
        final SecretKey key = this.keyStoreHelper.getKey("jwt-signing-key", this.masterKeystorePath, this.masterKeystorePassword);
        final String plainText = encryptRequest.getPlainText();
        final String jwt = encryptRequest.getJwt();

        this.nullOrBlankValidator.validateNullOrBlank(plainText, FieldName.PLAIN_TEXT);
        this.lengthValidator.validateLength(plainText, PLAIN_TEXT_MAX_LENGTH, FieldName.PLAIN_TEXT);
        this.asciiValidator.validateAscii(plainText, FieldName.PLAIN_TEXT);
        this.charsetValidator.validateCharset(plainText, FieldName.PLAIN_TEXT);
        this.controlCharValidator.validateControlChars(plainText, FieldName.PLAIN_TEXT);
        this.whitelistValidator.validateWhitelist(plainText, FieldName.PLAIN_TEXT, true);

        this.validateJwt(jwt, key, false);
    }

    /**
     * Validates the DecryptRequest for decryption.
     *
     * @param decryptRequest the DecryptRequest containing the cipher text and JWT
     * @param clientName  the name of the client making the request
     */
    public final void validateDecryptRequest(final DecryptRequest decryptRequest, final String clientName) {
        this.validateClientName(clientName);
        final SecretKey key = this.keyStoreHelper.getKey("jwt-signing-key", this.masterKeystorePath, this.masterKeystorePassword);
        final String jwt = decryptRequest.getJwt();
        final String cipherText = decryptRequest.getCipherText();

        this.nullOrBlankValidator.validateNullOrBlank(cipherText, FieldName.CIPHER_TEXT);
        this.lengthValidator.validateLength(cipherText, CIPHER_TEXT_MAX_LENGTH, FieldName.CIPHER_TEXT);
        this.asciiValidator.validateAscii(cipherText, FieldName.CIPHER_TEXT);
        this.charsetValidator.validateCharset(cipherText, FieldName.CIPHER_TEXT);
        this.controlCharValidator.validateControlChars(cipherText, FieldName.CIPHER_TEXT);
        this.base64Validator.validateBase64(cipherText, FieldName.CIPHER_TEXT);

        this.validateJwt(jwt, key, true);
    }

    /**
     * Validates the JWT string against the provided SecretKey.
     *
     * @param jwt the JWT string to validate
     * @param key the SecretKey used for signature validation
     *
     *            TODO vllt schuaen das der jwt validator nicht von den anderen validatoren abhängt, sondern DIE ANDEREN VALIDATOREN FÜR DEN ALGO HEADER KEYALIAS UND ISSUEDTO HIER DRIN AUFGERUFEN WERDEN:::
     */
    private void validateJwt(final String jwt, final SecretKey key, final boolean consumeJti) {
        this.nullOrBlankValidator.validateNullOrBlank(jwt, FieldName.JWT);
        this.lengthValidator.validateLength(jwt, JWT_MAX_LENGTH, FieldName.JWT);
        this.asciiValidator.validateAscii(jwt, FieldName.JWT);
        this.charsetValidator.validateCharset(jwt, FieldName.JWT);
        this.controlCharValidator.validateControlChars(jwt, FieldName.JWT);
        this.whitelistValidator.validateWhitelist(jwt, FieldName.JWT, false);

        this.jwtValidator.validateJwtPattern(jwt);

        final Jws<Claims> parsed = this.jwtValidator.validateSignature(jwt, key);
        final Claims claims = parsed.getBody();
        final JwsHeader<?> header = (JwsHeader<?>) parsed.getHeader();

        this.jwtValidator.validateExpiration(claims);
        this.jwtValidator.validateIssuerAndAudience(claims);

        final String keyAlias = claims.get("keyAlias", String.class);
        this.jwtValidator.validateKeyAlias(keyAlias, JWT_KEY_ALIAS_MAX_LENGTH);
        final String issuedTo = claims.get("issuedTo", String.class);
        this.jwtValidator.validateIssuedTo(issuedTo, ISSUED_TO_MAX_LENGTH);

        final String algorithm = header.getAlgorithm();
        this.jwtValidator.validateAlgorithmFromHeader(algorithm, JWT_ALGORITHM_MAX_LENGTH);

        if (consumeJti) {
            this.jwtValidator.validateAndConsumeJti(claims);
        }
    }

    /**
     * Validates the client name for various constraints.
     *
     * @param clientName the name of the client to validate
     */
    private void validateClientName(final String clientName) {
        this.nullOrBlankValidator.validateNullOrBlank(clientName, FieldName.CLIENT_NAME);
        this.lengthValidator.validateLength(clientName, CLIENT_NAME_MAX_LENGTH, FieldName.CLIENT_NAME);
        this.asciiValidator.validateAscii(clientName, FieldName.CLIENT_NAME);
        this.charsetValidator.validateCharset(clientName, FieldName.CLIENT_NAME);
        this.controlCharValidator.validateControlChars(clientName, FieldName.CLIENT_NAME);
        this.whitelistValidator.validateWhitelist(clientName, FieldName.CLIENT_NAME, false);
    }
}
