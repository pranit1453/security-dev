package com.pranit.security.shared.exception;

import org.springframework.http.HttpStatus;

public class OTPBlock extends BaseException {
    public OTPBlock(String message) {
        super(message, HttpStatus.BAD_REQUEST);
    }
}
