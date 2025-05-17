package com.projectwork.cryptoservice.businesslogic.jwtmanagement;

import java.time.Instant;
import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Service;

import com.projectwork.cryptoservice.businesslogic.keymanagement.ClientKeyRegistry;
import com.projectwork.cryptoservice.businesslogic.keymanagement.KeyStoreHelper;
import com.projectwork.cryptoservice.entity.factory.ResultModelsFactory;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtModel;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtResultModel;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class JwtManagementService {
    private final ResultModelsFactory resultModelsFactory;
    private final KeyStoreHelper keyStoreHelper;
    private final ClientKeyRegistry clientKeyRegistry;

    public GenerateJwtResultModel generateJwt(final GenerateJwtModel generateJwtModel) {
        SecretKey jwtSigningKey;
        try {
            jwtSigningKey = keyStoreHelper.getKey("jwt-signing-key");
        } catch (final Exception exception) {
            // TODO error handling
            throw new RuntimeException(exception);
        }

        final Instant now = Instant.now();
        final Instant expiration = now.plusSeconds(3600);
        final String keyAlias = clientKeyRegistry.getKeyAliasForClient(generateJwtModel.getClientName());
        final String jwt = Jwts.builder()
            .setSubject("CryptoMicroserviceAccesToken")
            .claim("keyAlias", keyAlias)
            .claim("issuedTo", generateJwtModel.getIssuedTo())
            .setIssuedAt(Date.from(now))
            .setExpiration(Date.from(expiration))
            .signWith(jwtSigningKey, SignatureAlgorithm.HS256)
            .compact();
        return resultModelsFactory.buildGenerateJwtResultModel(jwt);
    }

    public String extractClientKeyAlias(final String jwtToken) {
        SecretKey jwtSigningKey;
        try {
            jwtSigningKey = keyStoreHelper.getKey("jwt-signing-key");
        } catch (final Exception exception) {
            // TODO error handling
            throw new RuntimeException(exception);
        }
        return Jwts.parserBuilder()
            .setSigningKey(jwtSigningKey)
            .build()
            .parseClaimsJws(jwtToken)
            .getBody()
            .get("keyAlias", String.class);
    }

    public String extractIssuedTo(final String jwtToken){
        SecretKey jwtSigningKey;
        try {
            jwtSigningKey = keyStoreHelper.getKey("jwt-signing-key");
        } catch (final Exception exception) {
            // TODO error handling
            throw new RuntimeException(exception);
        }
        return Jwts.parserBuilder()
            .setSigningKey(jwtSigningKey)
            .build()
            .parseClaimsJws(jwtToken)
            .getBody()
            .get("issuedTo", String.class);
    }
}
