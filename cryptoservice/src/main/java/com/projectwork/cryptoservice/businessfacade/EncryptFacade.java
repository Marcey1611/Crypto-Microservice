package com.projectwork.cryptoservice.businessfacade;

import com.projectwork.cryptoservice.entity.*;
import com.projectwork.cryptoservice.businesslogic.EncryptService;
import org.springframework.stereotype.Service;

@Service
public class EncryptFacade {

    private final EncryptService encryptService;

    public EncryptFacade(EncryptService encryptService) {
        this.encryptService = encryptService;
    }

    public EncryptResultModel processEncryption(EncryptModel model) {
        return encryptService.encrypt(model);
    }
}
