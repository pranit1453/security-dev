package com.pranit.security.authentication.exception;

import com.pranit.security.shared.exception.BaseException;
import org.springframework.http.HttpStatus;

public class OAuth2Authentication extends BaseException {
    public OAuth2Authentication(String message) {
        super(message, HttpStatus.UNAUTHORIZED);
    }
}
