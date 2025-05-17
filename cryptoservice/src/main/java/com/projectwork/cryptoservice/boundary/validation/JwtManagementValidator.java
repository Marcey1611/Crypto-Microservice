package com.projectwork.cryptoservice.boundary.validation;

import org.springframework.stereotype.Component;

import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtRequest;

@Component
public class JwtManagementValidator extends BaseValidator {

    public void validateGenerateJwtRequest(final GenerateJwtRequest request) {
        final String issuedTo = request.getIssuedTo();

        checkNotBlank(issuedTo, "issuedTo");
        checkMaxLength(issuedTo, 64, "issuedTo");
        checkNoUnicodeEscapes(issuedTo, "issuedTo");
        checkWhitelist(issuedTo, "issuedTo");
    }
}

