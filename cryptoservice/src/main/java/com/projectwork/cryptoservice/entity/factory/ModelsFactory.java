package com.projectwork.cryptoservice.entity.factory;

import com.projectwork.cryptoservice.entity.models.decrypt.DecryptModel;
import com.projectwork.cryptoservice.entity.models.decrypt.DecryptRequest;
import com.projectwork.cryptoservice.entity.models.encrypt.EncryptModel;
import com.projectwork.cryptoservice.entity.models.encrypt.EncryptRequest;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtModel;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtRequest;
import com.projectwork.cryptoservice.entity.models.keymanagement.GenerateKeyModel;
import org.springframework.stereotype.Component;

/**
 * ModelsFactory class that creates instances of various models used in the cryptographic service.
 * This factory encapsulates the creation logic for models related to encryption, decryption, JWT generation, and TLS management.
 */
@Component
public class ModelsFactory {

    /**
     * Builds an EncryptModel instance based on the provided EncryptRequest and client name.
     *
     * @param encryptRequest the request containing the plain text and JWT
     * @param clientName the name of the client making the request
     * @return a new EncryptModel instance
     */
    public final EncryptModel buildEncryptModel(final EncryptRequest encryptRequest, final String clientName) {
        final String plainText = encryptRequest.getPlainText();
        final String jwt = encryptRequest.getJwt();
        return new EncryptModel(plainText, jwt, clientName);
    }

    /**
     * Builds a DecryptModel instance based on the provided DecryptRequest and client name.
     *
     * @param decryptRequest the request containing the cipher text and JWT
     * @param clientName the name of the client making the request
     * @return a new DecryptModel instance
     */
    public final DecryptModel buildDecryptModel(final DecryptRequest decryptRequest, final String clientName) {
        final String cipherText = decryptRequest.getCipherText();
        final String jwt = decryptRequest.getJwt();
        return new DecryptModel(cipherText, jwt, clientName);
    }

    /**
     * Builds a GenerateKeyModel instance based on the provided client name.
     *
     * @param clientNAme the name of the client for which the key is being generated
     * @return a new GenerateKeyModel instance
     */
    public final GenerateKeyModel buildGenerateKeyModel(final String clientNAme) {
        return new GenerateKeyModel(clientNAme);
    }

    /**
     * Builds a GenerateJwtModel instance based on the provided GenerateJwtRequest and client name.
     *
     * @param generateJwtRequest the request containing the parameters for JWT generation
     * @param clientName the name of the client making the request
     * @return a new GenerateJwtModel instance
     */
    public final GenerateJwtModel buildGenerateJwtModel(final GenerateJwtRequest generateJwtRequest, final String clientName) {
        final String issuedTo = generateJwtRequest.getIssuedTo();
        return new GenerateJwtModel(issuedTo, clientName);
    }
}
