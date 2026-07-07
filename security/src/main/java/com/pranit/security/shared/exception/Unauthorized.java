package com.pranit.security.shared.exception;

import org.springframework.http.HttpStatus;

public class Unauthorized extends BaseException {
    public Unauthorized(String message) {
        super(message, HttpStatus.UNAUTHORIZED);
    }
}
