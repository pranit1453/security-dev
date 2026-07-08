package com.pranit.security.shared.exception;

import org.springframework.http.HttpStatus;

public class OTPResend extends BaseException {
    public OTPResend(String message) {
        super(message, HttpStatus.BAD_REQUEST);
    }
}
