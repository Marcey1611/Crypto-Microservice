package com.projectwork.cryptoservice.entity.models.decrypt;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class DecryptResultModel {
    private final String plainText;
    
    public String getPlainText() { return plainText; }
}
