package com.pranit.security.authentication.controller;

import com.pranit.security.authentication.dto.ChangeForgotPasswordRequest;
import com.pranit.security.authentication.dto.ChangePasswordRequest;
import com.pranit.security.authentication.dto.ForgotPasswordEmail;
import com.pranit.security.authentication.dto.ForgotPasswordResponse;
import com.pranit.security.authentication.dto.VerificationResponse;
import com.pranit.security.authentication.dto.VerifyOtp;
import com.pranit.security.authentication.service.EmailVerificationService;
import com.pranit.security.authentication.service.PasswordService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/v1/password")
@RequiredArgsConstructor
@Validated
public class PasswordController {

    private final PasswordService passwordService;
    private final EmailVerificationService emailVerificationService;

    @PutMapping("/update")
    public ResponseEntity<String> changePassword(@RequestBody @Valid ChangePasswordRequest request, HttpServletResponse response) {
        passwordService.changePassword(request, response);
        return ResponseEntity.ok("Change Password Successfully");
    }

    @PostMapping("/reset/request")
    public ResponseEntity<String> requestPasswordReset(@RequestBody @Valid ForgotPasswordEmail request) {
        passwordService.requestPasswordReset(request);
        return ResponseEntity.ok("Forgot password OTP sent successfully");
    }

    @PostMapping("/reset/verify")
    public ResponseEntity<VerificationResponse> verifyPasswordResetOtp(@RequestBody @Valid VerifyOtp request) {
        return ResponseEntity.ok(emailVerificationService.verifyPasswordResetOtp(request));
    }

    @PutMapping("/reset")
    public ResponseEntity<ForgotPasswordResponse> resetPassword(@RequestBody @Valid ChangeForgotPasswordRequest request) {
        return ResponseEntity.ok(passwordService.resetPassword(request));
    }

}
