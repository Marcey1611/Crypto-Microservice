package com.projectwork.cryptoservice.businesslogic.jwtmanagement;

import java.security.PrivateKey;
import java.time.Instant;
import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Service;

import com.projectwork.cryptoservice.businesslogic.keymanagement.ClientKeyAliasMap;
import com.projectwork.cryptoservice.businesslogic.keymanagement.KeyStoreHelper;
import com.projectwork.cryptoservice.entity.jwtmanagement.GenerateJwtModel;
import com.projectwork.cryptoservice.entity.jwtmanagement.GenerateJwtResultModel;
import com.projectwork.cryptoservice.factory.ResultModelsFactory;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Service
public class JwtManagementService {
    private final ResultModelsFactory resultModelsFactory;
    private final KeyStoreHelper keyStoreHelper;
    private final ClientKeyAliasMap clientKeyAliasMap;

    public JwtManagementService(final ResultModelsFactory resultModelsFactory, final KeyStoreHelper keyStoreHelper, final ClientKeyAliasMap clientKeyAliasMap) {
        this.clientKeyAliasMap = clientKeyAliasMap;
        this.keyStoreHelper = keyStoreHelper;
        this.resultModelsFactory = resultModelsFactory;
    }

    public GenerateJwtResultModel generateJwt(GenerateJwtModel generateJwtModel) {
        SecretKey jwtSigningKey;
        try {
            jwtSigningKey = keyStoreHelper.getKey("jwt-signing-key");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        final Instant now = Instant.now();
        final Instant expiration = now.plusSeconds(3600);
        final String keyAlias = clientKeyAliasMap.getKeyAlias(generateJwtModel.getClientName());
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
}
