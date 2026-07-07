package com.pranit.security.shared.exception;

import org.springframework.http.HttpStatus;

public class OTPValidation extends BaseException {
    public OTPValidation(String message) {
        super(message, HttpStatus.BAD_REQUEST);
    }
}
