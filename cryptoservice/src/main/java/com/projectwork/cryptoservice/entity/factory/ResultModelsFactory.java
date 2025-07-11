package com.projectwork.cryptoservice.entity.factory;

import com.projectwork.cryptoservice.entity.models.decrypt.DecryptResultModel;
import com.projectwork.cryptoservice.entity.models.encrypt.EncryptResultModel;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtResultModel;
import com.projectwork.cryptoservice.entity.models.keymanagement.GenerateKeyResultModel;
import org.springframework.stereotype.Component;

/**
 * ResultModelsFactory class that creates instances of result models used in the cryptographic service.
 * This factory encapsulates the creation logic for models related to key generation, JWT generation, encryption, decryption, and TLS management.
 */
@Component
public class ResultModelsFactory {

    /**
     * Builds a GenerateKeyResultModel instance with the specified message.
     *
     * @param message the message associated with the key generation result
     * @return a new GenerateKeyResultModel instance
     */
    public final GenerateKeyResultModel buildGenerateKeyResultModel(final String message) {
        return new GenerateKeyResultModel(message);
    }

    /**
     * Builds a GenerateJwtResultModel instance with the specified JWT.
     *
     * @param jwt the JSON Web Token (JWT) to be included in the result model
     * @return a new GenerateJwtResultModel instance
     */
    public final GenerateJwtResultModel buildGenerateJwtResultModel(final String jwt) {
        return new GenerateJwtResultModel(jwt);
    }

    /**
     * Builds an EncryptResultModel instance with the specified cipher text.
     *
     * @param cipherText the encrypted text to be included in the result model
     * @return a new EncryptResultModel instance
     */
    public final EncryptResultModel buildEncryptResultModel(final String cipherText) {
        return new EncryptResultModel(cipherText);
    }

    /**
     * Builds a DecryptResultModel instance with the specified plain text.
     *
     * @param plainText the decrypted text to be included in the result model
     * @return a new DecryptResultModel instance
     */
    public final DecryptResultModel buildDecryptResultModel(final String plainText) {
        return new DecryptResultModel(plainText);
    }
}
