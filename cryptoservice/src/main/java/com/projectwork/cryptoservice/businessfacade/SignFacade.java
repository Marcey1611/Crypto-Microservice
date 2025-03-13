package com.projectwork.cryptoservice.businessfacade;

import com.projectwork.cryptoservice.entity.sign.SignModel;
import com.projectwork.cryptoservice.entity.sign.SignResultModel;
import com.projectwork.cryptoservice.businesslogic.SignService;
import org.springframework.stereotype.Service;

@Service
public class SignFacade {

    private final SignService signService;

    public SignFacade(SignService signService) {
        this.signService = signService;
    }

    public SignResultModel processSigning(SignModel signModel) {
        return signService.sign(signModel);
    }
}
