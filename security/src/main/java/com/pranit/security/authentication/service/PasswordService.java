package com.pranit.security.authentication.service;

import com.pranit.security.authentication.dto.ChangeForgotPasswordRequest;
import com.pranit.security.authentication.dto.ChangePasswordRequest;
import com.pranit.security.authentication.dto.ForgotPasswordEmail;
import com.pranit.security.authentication.dto.ForgotPasswordResponse;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

public interface PasswordService {

    void requestPasswordReset(@Valid ForgotPasswordEmail request);

    ForgotPasswordResponse resetPassword(@Valid ChangeForgotPasswordRequest request);

    void changePassword(@Valid ChangePasswordRequest request, HttpServletResponse response);
}
