package com.projectwork.cryptoservice.businessfacade;

import com.projectwork.cryptoservice.entity.*;
import com.projectwork.cryptoservice.businesslogic.DecryptService;
import org.springframework.stereotype.Service;

@Service
public class DecryptFacade {

    private final DecryptService decryptService;

    public DecryptFacade(DecryptService decryptService) {
        this.decryptService = decryptService;
    }

    public DecryptResultModel processDecryption(DecryptModel decryptModel) {
        return decryptService.decrypt(decryptModel);
    }
}
