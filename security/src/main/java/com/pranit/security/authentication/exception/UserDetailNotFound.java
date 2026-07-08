package com.pranit.security.authentication.exception;

import com.pranit.security.shared.exception.BaseException;
import org.springframework.http.HttpStatus;

public class UserDetailNotFound extends BaseException {
    public UserDetailNotFound(String message) {
        super(message, HttpStatus.NOT_FOUND);
    }
}
