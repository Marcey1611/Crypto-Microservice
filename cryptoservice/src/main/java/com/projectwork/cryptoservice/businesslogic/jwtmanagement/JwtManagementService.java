package com.projectwork.cryptoservice.businesslogic.jwtmanagement;

import com.projectwork.cryptoservice.boundary.validation.cache.ReplayCache;
import com.projectwork.cryptoservice.businesslogic.keymanagement.ClientKeyRegistry;
import com.projectwork.cryptoservice.businesslogic.keymanagement.KeyStoreHelper;
import com.projectwork.cryptoservice.entity.factory.ResultModelsFactory;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtModel;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtResultModel;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorHandler;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

/**
 * JwtManagementService class that handles the generation and management of JWTs.
 * It uses KeyStoreHelper to retrieve the signing key and ClientKeyRegistry to manage client keys.
 * SCPs:
 * - [114] Logging controls should support both success and failure of specified security events
 */
@RequiredArgsConstructor
@Service
public class JwtManagementService {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtManagementService.class);

    private final ResultModelsFactory resultModelsFactory;
    private final KeyStoreHelper keyStoreHelper;
    private final ClientKeyRegistry clientKeyRegistry;
    private final ErrorHandler errorHandler;
    private final ReplayCache replayCache;

    @Value("${master.keystore.path}")
    private String masterKeystorePath;

    @Value("${master.keystore.password}")
    private String masterKeystorePassword;

    /**
     * Generates a JWT based on the provided GenerateJwtModel.
     *
     * @param generateJwtModel the model containing parameters for JWT generation
     * @return a GenerateJwtResultModel containing the generated JWT
     */
    public final GenerateJwtResultModel generateJwt(final GenerateJwtModel generateJwtModel) {
        final String clientName = generateJwtModel.getClientName();
        final String issuedTo = generateJwtModel.getIssuedTo();

        LOGGER.info("Generating JWT for current client.");

        final SecretKey jwtSigningKey = this.keyStoreHelper.getKey("jwt-signing-key", this.masterKeystorePath, this.masterKeystorePassword);
        final Instant now = Instant.now();
        final String keyAlias = this.clientKeyRegistry.getKeyAliasForClient(clientName);
        final byte[] randomBytes = new byte[16];

        try {
            SecureRandom secureRandom = SecureRandom.getInstanceStrong();
            secureRandom.nextBytes(randomBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        final String jti = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);

        final String jwt;
        try {
            jwt = Jwts.builder()
                    .setIssuer(JwtConsts.ISSUER)
                    .setAudience(JwtConsts.AUDIENCE)
                    .setId(jti)
                    .setSubject("CryptoMicroserviceAccesToken")
                    .claim("keyAlias", keyAlias)
                    .claim("issuedTo", issuedTo)
                    .setIssuedAt(Date.from(now))
                    .setExpiration(Date.from(now.plusSeconds(JwtConsts.TOKEN_TTL_SECONDS)))
                    .signWith(jwtSigningKey, SignatureAlgorithm.HS256)
                    .compact();
        } catch (final JwtException | IllegalArgumentException | SecurityException exception) {
            throw this.errorHandler.handleBusinessError(
                    ErrorCode.JWT_GENERATION_FAILED,
                    clientName,
                    "While generating JWT for current client.",
                    exception
            );
        }

        replayCache.register(jti, now.plusSeconds(JwtConsts.TOKEN_TTL_SECONDS).getEpochSecond());
        LOGGER.info("JWT successfully generated for current client.");
        return this.resultModelsFactory.buildGenerateJwtResultModel(jwt);
    }

    /**
     * Extracts the client key alias from the provided JWT token.
     *
     * @param jwtToken the JWT token from which to extract the key alias
     * @return the client key alias
     */
    public final String extractClientKeyAlias(final String jwtToken) {
        LOGGER.debug("Extracting keyAlias from JWT");

        final SecretKey jwtSigningKey = this.keyStoreHelper.getKey("jwt-signing-key", this.masterKeystorePath, this.masterKeystorePassword);
        final String keyAlias;

        try {
            keyAlias = Jwts.parserBuilder()
                    .setSigningKey(jwtSigningKey)
                    .build()
                    .parseClaimsJws(jwtToken)
                    .getBody()
                    .get("keyAlias", String.class);


        } catch (final JwtException | IllegalArgumentException exception) {
            throw this.errorHandler.handleBusinessError(
                    ErrorCode.JWT_KEYALIAS_EXTRACTION_FAILED,
                    "While extracting keyAlias from JWT",
                    exception
            );
        }

        LOGGER.debug("Extracted keyAlias successfully.");
        return keyAlias;
    }


    /**
     * Extracts the issuedTo field from the provided JWT token.
     *
     * @param jwtToken the JWT token from which to extract the issuedTo field
     * @return the issuedTo value
     */
    public final String extractIssuedTo(final String jwtToken) {
        LOGGER.debug("Extracting issuedTo from JWT");

        final SecretKey jwtSigningKey = this.keyStoreHelper.getKey("jwt-signing-key", this.masterKeystorePath, this.masterKeystorePassword);
        final String issuedTo;

        try {
            issuedTo = Jwts.parserBuilder()
                    .setSigningKey(jwtSigningKey)
                    .build()
                    .parseClaimsJws(jwtToken)
                    .getBody()
                    .get("issuedTo", String.class);


        } catch (final JwtException | IllegalArgumentException exception) {
            throw this.errorHandler.handleBusinessError(
                    ErrorCode.JWT_ISSUEDTO_EXTRACTION_FAILED,
                    "While extracting issuedTo from JWT",
                    exception
            );
        }

        LOGGER.debug("Extracted issuedTo successfully.");
        return issuedTo;
    }
}
