package com.pranit.security.otp.exception;

import com.pranit.security.shared.exception.BaseException;
import org.springframework.http.HttpStatus;

public class OTPExpired extends BaseException {
    public OTPExpired(String message) {
        super(message, HttpStatus.BAD_REQUEST);
    }
}
