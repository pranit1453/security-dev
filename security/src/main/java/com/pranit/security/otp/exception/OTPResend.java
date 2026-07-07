package com.pranit.security.otp.exception;

import com.pranit.security.shared.exception.BaseException;
import org.springframework.http.HttpStatus;

public class OTPResend extends BaseException {
    public OTPResend(String message) {
        super(message, HttpStatus.BAD_REQUEST);
    }
}
