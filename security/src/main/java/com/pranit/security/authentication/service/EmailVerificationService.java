package com.pranit.security.authentication.service;


import com.pranit.security.authentication.dto.EmailRequest;
import com.pranit.security.authentication.dto.ResendOtpRequest;
import com.pranit.security.authentication.dto.VerificationResponse;
import com.pranit.security.authentication.dto.VerifyEmail;
import com.pranit.security.authentication.dto.VerifyOtp;
import jakarta.validation.Valid;

public interface EmailVerificationService {

    VerificationResponse verifyRegistration(@Valid VerifyOtp request);

    VerificationResponse verifyPasswordResetOtp(@Valid VerifyOtp request);

    void resendVerificationOtp(@Valid ResendOtpRequest request);

    void requestCurrentEmailVerification(@Valid VerifyEmail request);

    VerificationResponse confirmCurrentEmailVerification(@Valid VerifyOtp request);

    void requestEmailChange(@Valid EmailRequest request);

    VerificationResponse confirmEmailChange(@Valid VerifyOtp request);
}
