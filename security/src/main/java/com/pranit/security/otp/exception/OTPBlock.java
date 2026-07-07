package com.pranit.security.otp.exception;

import com.pranit.security.shared.exception.BaseException;
import org.springframework.http.HttpStatus;

public class OTPBlock extends BaseException {
    public OTPBlock(String message) {
        super(message, HttpStatus.BAD_REQUEST);
    }
}
