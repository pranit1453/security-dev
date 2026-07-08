package com.pranit.security.authentication.exception;

import com.pranit.security.shared.exception.BaseException;
import org.springframework.http.HttpStatus;

public class RoleNotFound extends BaseException {
    public RoleNotFound(String message) {
        super(message, HttpStatus.NOT_FOUND);
    }
}
