package com.pranit.security.authentication.service;


import com.pranit.security.shared.event.OtpEvent;
import com.pranit.security.shared.event.SecurityEvent;
import com.pranit.security.shared.event.WelcomeEvent;

public interface EventPublisherService {

    void sendVerificationOtp(OtpEvent data);

    void sendWelcomeMessage(WelcomeEvent data);

    void sendPasswordChangeOtp(OtpEvent data);

    void sendEmailChangeOtp(OtpEvent data);

    void sendSecurityAlertToOldEmail(SecurityEvent data);

    void sendEmailVerifyData(OtpEvent data);
}
