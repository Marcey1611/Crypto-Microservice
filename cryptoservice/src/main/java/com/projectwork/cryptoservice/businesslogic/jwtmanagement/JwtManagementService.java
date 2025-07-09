package com.projectwork.cryptoservice.businesslogic.jwtmanagement;

import com.projectwork.cryptoservice.businesslogic.keymanagement.ClientKeyRegistry;
import com.projectwork.cryptoservice.businesslogic.keymanagement.KeyStoreHelper;
import com.projectwork.cryptoservice.entity.factory.ResultModelsFactory;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtModel;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtResultModel;
import com.projectwork.cryptoservice.errorhandling.exceptions.InternalServerErrorException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorDetail;
import com.projectwork.cryptoservice.errorhandling.util.ErrorDetailBuilder;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;

/**
 * JwtManagementService class that handles the generation and management of JWTs.
 * It uses KeyStoreHelper to retrieve the signing key and ClientKeyRegistry to manage client keys.
 */
@RequiredArgsConstructor
@Service
public class JwtManagementService {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtManagementService.class);

    private final ResultModelsFactory resultModelsFactory;
    private final KeyStoreHelper keyStoreHelper;
    private final ClientKeyRegistry clientKeyRegistry;

    /**
     * Generates a JWT based on the provided GenerateJwtModel.
     *
     * @param generateJwtModel the model containing parameters for JWT generation
     * @return a GenerateJwtResultModel containing the generated JWT
     */
    public final GenerateJwtResultModel generateJwt(final GenerateJwtModel generateJwtModel) {
        final String clientName = generateJwtModel.getClientName();
        final String issuedTo = generateJwtModel.getIssuedTo();

        LOGGER.info("Generating JWT for client '{}', issuedTo '{}'", clientName, issuedTo);

        final SecretKey jwtSigningKey = this.keyStoreHelper.getKey("jwt-signing-key");
        final Instant now = Instant.now();
        final Instant expiration = now.plusSeconds(3600L);
        final String keyAlias = this.clientKeyRegistry.getKeyAliasForClient(clientName);
        final Date fromNow = Date.from(now);
        final Date fromExpiration = Date.from(expiration);

        LOGGER.debug("JWT claims: keyAlias='{}', issuedTo='{}', expiresAt='{}'", keyAlias, issuedTo, fromExpiration);

        final String jwt;
        try {
            jwt = Jwts.builder()
                    .setSubject("CryptoMicroserviceAccesToken")
                    .claim("keyAlias", keyAlias)
                    .claim("issuedTo", issuedTo)
                    .setIssuedAt(fromNow)
                    .setExpiration(fromExpiration)
                    .signWith(jwtSigningKey, SignatureAlgorithm.HS256)
                    .compact();
        } catch (final JwtException | IllegalArgumentException | SecurityException exception) {
            final ErrorCode errorCode = ErrorCode.JWT_GENERATION_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withLogMsgFormatted(clientName);
            errorDetailBuilder.withContext("While generating JWT for client: " + clientName);
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            errorDetail.logErrorWithException();
            throw new InternalServerErrorException(errorDetail);
        }

        LOGGER.info("JWT successfully generated for client '{}'", clientName);
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

        final SecretKey jwtSigningKey = this.keyStoreHelper.getKey("jwt-signing-key");
        final String keyAlias;

        try {
            keyAlias = Jwts.parserBuilder()
                    .setSigningKey(jwtSigningKey)
                    .build()
                    .parseClaimsJws(jwtToken)
                    .getBody()
                    .get("keyAlias", String.class);


        } catch (final JwtException | IllegalArgumentException exception) {
            final ErrorCode errorCode = ErrorCode.JWT_KEYALIAS_EXTRACTION_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While extracting keyAlias from JWT");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            errorDetail.logErrorWithException();
            throw new InternalServerErrorException(errorDetail);
        }

        LOGGER.debug("Extracted keyAlias: '{}'", keyAlias);
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

        final SecretKey jwtSigningKey = this.keyStoreHelper.getKey("jwt-signing-key");
        final String issuedTo;

        try {
            issuedTo = Jwts.parserBuilder()
                    .setSigningKey(jwtSigningKey)
                    .build()
                    .parseClaimsJws(jwtToken)
                    .getBody()
                    .get("issuedTo", String.class);


        } catch (final JwtException | IllegalArgumentException exception) {
            final ErrorCode errorCode = ErrorCode.JWT_ISSUEDTO_EXTRACTION_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While extracting issued to from JWT");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            errorDetail.logErrorWithException();
            throw new InternalServerErrorException(errorDetail);
        }

        LOGGER.debug("Extracted issuedTo: '{}'", issuedTo);
        return issuedTo;
    }
}
