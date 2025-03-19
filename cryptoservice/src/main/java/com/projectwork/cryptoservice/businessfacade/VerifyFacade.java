package com.projectwork.cryptoservice.businessfacade;

import com.projectwork.cryptoservice.entity.verify.VerifyModel;
import com.projectwork.cryptoservice.entity.verify.VerifyResultModel;
import com.projectwork.cryptoservice.businesslogic.VerifyService;
import org.springframework.stereotype.Service;

@Service
public class VerifyFacade {

    private final VerifyService verifyService;

    public VerifyFacade(VerifyService verifyService) {
        this.verifyService = verifyService;
    }

    public VerifyResultModel processVerification(VerifyModel verifyModel) {
        return verifyService.verify(verifyModel);
    }
}
