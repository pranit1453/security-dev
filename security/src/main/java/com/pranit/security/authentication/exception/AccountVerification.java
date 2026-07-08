package com.pranit.security.authentication.exception;

import com.pranit.security.shared.exception.BaseException;
import org.springframework.http.HttpStatus;

public class AccountVerification extends BaseException {
    public AccountVerification(String message) {
        super(message, HttpStatus.BAD_REQUEST);
    }
}
