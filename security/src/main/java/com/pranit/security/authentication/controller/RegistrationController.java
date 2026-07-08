package com.pranit.security.authentication.controller;

import com.pranit.security.authentication.dto.RegistrationRequest;
import com.pranit.security.authentication.dto.ResendOtpRequest;
import com.pranit.security.authentication.dto.SignupResponse;
import com.pranit.security.authentication.dto.VerificationResponse;
import com.pranit.security.authentication.dto.VerifyOtp;
import com.pranit.security.authentication.service.EmailVerificationService;
import com.pranit.security.authentication.service.RegistrationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/register")
@RequiredArgsConstructor
@Validated
public class RegistrationController {

    private final RegistrationService registrationService;
    private final EmailVerificationService emailVerificationService;

    @PostMapping("/user")
    public ResponseEntity<SignupResponse> registerUser(@RequestBody @Valid RegistrationRequest request) {
        return ResponseEntity.ok(registrationService.createNewUserAccount(request));
    }

    @PostMapping("/admin")
    public ResponseEntity<SignupResponse> registerAdmin(@RequestBody @Valid RegistrationRequest request) {
        return ResponseEntity.ok(registrationService.createNewAdminAccount(request));
    }

    @PostMapping("/verify")
    public ResponseEntity<VerificationResponse> verifyRegistration(@RequestBody @Valid VerifyOtp request) {
        return ResponseEntity.ok(emailVerificationService.verifyRegistration(request));
    }

    @PostMapping("/verify/resend")
    public ResponseEntity<String> resendVerificationOtp(@RequestBody @Valid ResendOtpRequest request) {
        emailVerificationService.resendVerificationOtp(request);
        return ResponseEntity.ok("Verification OTP resent successfully to email");
    }
}
