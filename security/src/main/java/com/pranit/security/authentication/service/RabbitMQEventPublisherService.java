package com.pranit.security.authentication.service;


import com.pranit.security.shared.event.OtpEvent;
import com.pranit.security.shared.event.SecurityEvent;
import com.pranit.security.shared.event.WelcomeEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RabbitMQEventPublisherService implements EventPublisherService {
    @Override
    public void sendVerificationOtp(OtpEvent data) {
        
    }

    @Override
    public void sendWelcomeMessage(WelcomeEvent data) {

    }

    @Override
    public void sendPasswordChangeOtp(OtpEvent data) {

    }

    @Override
    public void sendEmailChangeOtp(OtpEvent data) {

    }

    @Override
    public void sendSecurityAlertToOldEmail(SecurityEvent data) {

    }

    @Override
    public void sendEmailVerifyData(OtpEvent data) {

    }

//    private final StreamBridge streamBridge;
//
//    @Override
//    public void sendVerificationOtp(RegistrationEmailVerificationData data) {
//        streamBridge.send("otpVerificationEvent-out-0", data);
//    }
//
//    @Override
//    public void sendWelcomeMessage(WelcomeUserData data) {
//        streamBridge.send("welcomeUserEvent-out-0", data);
//    }
//
//    @Override
//    public void sendPasswordChangeOtp(PasswordChangeData data) {
//        streamBridge.send("otpPasswordChangeEvent-out-0", data);
//    }
//
//    @Override
//    public void sendEmailChangeOtp(EmailChangeData data) {
//        streamBridge.send("otpEmailChangeEvent-out-0", data);
//    }
//
//    @Override
//    public void sendSecurityAlertToOldEmail(EmailData data) {
//        streamBridge.send("emailChangeSecurityAlertEvent-out-0", data);
//    }
//
//    @Override
//    public void sendEmailVerifyData(EmailVerifyData data) {
//        streamBridge.send("verifyCurrentEmailEvent-out-0",data);
//    }

}
