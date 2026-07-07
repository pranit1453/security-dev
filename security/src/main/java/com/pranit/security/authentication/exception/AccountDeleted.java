package com.pranit.security.authentication.exception;

import com.pranit.security.shared.exception.BaseException;
import org.springframework.http.HttpStatus;

public class AccountDeleted extends BaseException {
    public AccountDeleted(String message) {
        super(message, HttpStatus.BAD_REQUEST);
    }
}
