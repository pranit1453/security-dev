package com.pranit.security.authentication.exception;

import com.pranit.security.shared.exception.BaseException;
import org.springframework.http.HttpStatus;

public class TokenOwner extends BaseException {
    public TokenOwner(String message) {
        super(message, HttpStatus.BAD_REQUEST);
    }
}
