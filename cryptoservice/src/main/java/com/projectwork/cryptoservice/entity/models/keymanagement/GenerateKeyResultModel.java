package com.projectwork.cryptoservice.entity.models.keymanagement;

import lombok.Getter;

/**
 * GenerateKeyResultModel class that represents the result of generating a client key.
 * It contains a message indicating the result of the key generation process.
 */
@Getter
public class GenerateKeyResultModel {
    private String message = "Client key generated.";

    /**
     * Default constructor that initializes the message to a default value.
     * @param message the message indicating the result of the key generation process
     */
    public GenerateKeyResultModel(final String message) {
        this.message = message;
    }
}
