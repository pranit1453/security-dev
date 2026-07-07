package com.pranit.security.otp.exception;

import com.pranit.security.shared.exception.BaseException;
import org.springframework.http.HttpStatus;

public class OTPValidation extends BaseException {
    public OTPValidation(String message) {
        super(message, HttpStatus.BAD_REQUEST);
    }
}
