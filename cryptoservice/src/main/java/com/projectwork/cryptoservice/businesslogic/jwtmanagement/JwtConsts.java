package com.projectwork.cryptoservice.businesslogic.jwtmanagement;

public final class JwtConsts {
    public static final String ISSUER = "CryptoService";
    public static final String AUDIENCE = "/crypto/decrypt";
    public static final long   TOKEN_TTL_SECONDS = 90;   // 60–120
    public static final long   CLOCK_SKEW_SECONDS = 30;  // kleine Toleranz
}
