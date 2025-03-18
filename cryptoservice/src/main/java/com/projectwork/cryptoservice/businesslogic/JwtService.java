package com.projectwork.cryptoservice.businesslogic;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.util.Date;

import javax.crypto.SecretKey;

@Component
public class JwtService {
    public KeyStoreHelper keyStoreHelper;

    public JwtService (KeyStoreHelper keyStoreHelper) {
        this.keyStoreHelper = keyStoreHelper;
    }

    private Key getSigningKey() {
        try {
            return (SecretKey) keyStoreHelper.getKey("jwt-signing-key");
        } catch (Exception e) {
            throw new RuntimeException("JWT Signing Key konnte nicht aus dem Keystore geladen werden!", e);
        }
    }

    public String generateJwt(String keyAlias) {
        return Jwts.builder()
                .claim("keyAlias", keyAlias)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600000))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String getKeyAliasFromJwt(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

        return claims.get("keyAlias", String.class);
    }
}
