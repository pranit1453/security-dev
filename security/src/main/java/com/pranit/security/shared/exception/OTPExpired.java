package com.pranit.security.shared.exception;

import org.springframework.http.HttpStatus;

public class OTPExpired extends BaseException {
    public OTPExpired(String message) {
        super(message, HttpStatus.BAD_REQUEST);
    }
}
