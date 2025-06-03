package com.projectwork.cryptoservice.businesslogic.jwtmanagement;

import java.time.Instant;
import java.util.Date;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.projectwork.cryptoservice.businesslogic.keymanagement.ClientKeyRegistry;
import com.projectwork.cryptoservice.businesslogic.keymanagement.KeyStoreHelper;
import com.projectwork.cryptoservice.entity.factory.ResultModelsFactory;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtModel;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtResultModel;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;

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
        final SecretKey jwtSigningKey = this.keyStoreHelper.getKey("jwt-signing-key");
        final Instant now = Instant.now();
        final Instant expiration = now.plusSeconds(3600L);
        final String clientName = generateJwtModel.getClientName();
        final String keyAlias = this.clientKeyRegistry.getKeyAliasForClient(clientName);
        final String issuedTo = generateJwtModel.getIssuedTo();
        final Date fromNow = Date.from(now);
        final Date fromExpiration = Date.from(expiration);
        final String jwt = Jwts.builder()
            .setSubject("CryptoMicroserviceAccesToken")
            .claim("keyAlias", keyAlias)
            .claim("issuedTo", issuedTo)
            .setIssuedAt(fromNow)
            .setExpiration(fromExpiration)
            .signWith(jwtSigningKey, SignatureAlgorithm.HS256)
            .compact();
        return this.resultModelsFactory.buildGenerateJwtResultModel(jwt);
    }

    /**
     * Extracts the client key alias from the provided JWT token.
     *
     * @param jwtToken the JWT token from which to extract the key alias
     * @return the client key alias
     */
    public final String extractClientKeyAlias(final String jwtToken) {
        final SecretKey jwtSigningKey = this.keyStoreHelper.getKey("jwt-signing-key");
        return Jwts.parserBuilder()
            .setSigningKey(jwtSigningKey)
            .build()
            .parseClaimsJws(jwtToken)
            .getBody()
            .get("keyAlias", String.class);
    }

    /**
     * Extracts the issuedTo field from the provided JWT token.
     *
     * @param jwtToken the JWT token from which to extract the issuedTo field
     * @return the issuedTo value
     */
    public final String extractIssuedTo(final String jwtToken){
        final SecretKey jwtSigningKey = this.keyStoreHelper.getKey("jwt-signing-key");
        return Jwts.parserBuilder()
            .setSigningKey(jwtSigningKey)
            .build()
            .parseClaimsJws(jwtToken)
            .getBody()
            .get("issuedTo", String.class);
    }
}
