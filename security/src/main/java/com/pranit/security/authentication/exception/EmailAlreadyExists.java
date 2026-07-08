package com.pranit.security.authentication.exception;

import com.pranit.security.shared.exception.BaseException;
import org.springframework.http.HttpStatus;

public class EmailAlreadyExists extends BaseException {
    public EmailAlreadyExists(String message) {
        super(message, HttpStatus.CONFLICT);
    }
}
