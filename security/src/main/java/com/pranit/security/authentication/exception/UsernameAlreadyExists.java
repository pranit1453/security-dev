package com.pranit.security.authentication.exception;

import com.pranit.security.shared.exception.BaseException;
import org.springframework.http.HttpStatus;

public class UsernameAlreadyExists extends BaseException {
    public UsernameAlreadyExists(String message) {
        super(message, HttpStatus.CONFLICT);
    }
}
