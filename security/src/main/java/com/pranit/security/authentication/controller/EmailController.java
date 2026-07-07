package com.pranit.security.authentication.controller;

import com.pranit.security.authentication.dto.EmailRequest;
import com.pranit.security.authentication.dto.VerificationResponse;
import com.pranit.security.authentication.dto.VerifyEmail;
import com.pranit.security.authentication.dto.VerifyOtp;
import com.pranit.security.authentication.service.EmailVerificationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/v1/email")
@RequiredArgsConstructor
@Validated
public class EmailController {

    private final EmailVerificationService emailVerificationService;

    @PostMapping("/verification/current/request")
    public ResponseEntity<String> requestCurrentEmailVerification(@RequestBody @Valid VerifyEmail request) {
        emailVerificationService.requestCurrentEmailVerification(request);
        return ResponseEntity.ok("Email change OTP sent successfully");
    }

    @PostMapping("/verification/current/confirm")
    public ResponseEntity<VerificationResponse> confirmCurrentEmailVerification(@RequestBody @Valid VerifyOtp request) {
        return ResponseEntity.ok(emailVerificationService.confirmCurrentEmailVerification(request));
    }

    @PostMapping("/change/request")
    public ResponseEntity<String> requestEmailChange(@RequestBody @Valid EmailRequest request) {
        emailVerificationService.requestEmailChange(request);
        return ResponseEntity.ok("Email change OTP sent successfully");
    }

    @PostMapping("/change/confirm")
    public ResponseEntity<VerificationResponse> confirmEmailChange(@RequestBody @Valid VerifyOtp request) {
        return ResponseEntity.ok(emailVerificationService.confirmEmailChange(request));
    }
}
