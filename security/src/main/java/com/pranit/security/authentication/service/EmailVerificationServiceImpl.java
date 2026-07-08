package com.pranit.security.authentication.service;

import com.pranit.security.authentication.dto.EmailRequest;
import com.pranit.security.authentication.dto.ResendOtpRequest;
import com.pranit.security.authentication.dto.VerificationResponse;
import com.pranit.security.authentication.dto.VerifyEmail;
import com.pranit.security.authentication.dto.VerifyOtp;
import com.pranit.security.authentication.entity.UserDetail;
import com.pranit.security.authentication.exception.AccountVerification;
import com.pranit.security.authentication.exception.EmailAlreadyExists;
import com.pranit.security.authentication.exception.EmailNotFound;
import com.pranit.security.authentication.exception.UserDetailNotFound;
import com.pranit.security.authentication.repository.UserRepository;
import com.pranit.security.otp.api.OtpGeneration;
import com.pranit.security.shared.constants.OtpType;
import com.pranit.security.shared.event.OtpEvent;
import com.pranit.security.shared.event.SecurityEvent;
import com.pranit.security.shared.event.WelcomeEvent;
import com.pranit.security.shared.exception.OTPExpired;
import com.pranit.security.shared.exception.OTPValidation;
import com.pranit.security.shared.exception.Unauthorized;
import com.pranit.security.shared.helper.Generate;
import com.pranit.security.shared.helper.SecurityContext;
import com.pranit.security.shared.redis.RedisOtpStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailVerificationServiceImpl implements EmailVerificationService {

    private final UserRepository userRepository;
    private final RedisOtpStore redisOtpStore;
    private final PasswordEncoder passwordEncoder;
    private final EventPublisherService eventPublisherService;
    private final OtpGeneration otpGeneration;

    @Override
    @Transactional
    public VerificationResponse verifyRegistration(final VerifyOtp request) {
        final String email = request.email();
        final OtpType type = OtpType.REGISTRATION;
        final UserDetail userDetail = findUserByEmail(email);
        validateOtp(request.otp(), userDetail.getEmail(), type);
        activateAccount(userDetail);
        redisOtpStore.clearAll(null, userDetail.getEmail(), type);
        final WelcomeEvent data = WelcomeEvent.builder()
                .eventId(Generate.generateEventId())
                .username(userDetail.getUsername())
                .email(userDetail.getEmail())
                .build();
        log.info("Sending Welcome email to username: {}", userDetail.getUsername());
        eventPublisherService.sendWelcomeMessage(data);
        return VerificationResponse.builder()
                .status(true)
                .message("Account verified successfully.")
                .build();
    }

    @Override
    @Transactional
    public VerificationResponse verifyPasswordResetOtp(final VerifyOtp request) {
        final String email = request.email();
        final OtpType type = OtpType.PASSWORD_CHANGE;
        final UserDetail userCredential = findUserByEmail(email);
        final String storedHashedOtp = redisOtpStore.getOtp
                (userCredential.getUserId(), userCredential.getEmail(), type);
        otpValidation(userCredential.getUserId(), userCredential.getEmail(), request.otp(), storedHashedOtp, type);
        log.info("Password change OTP verified successfully for userId: {}", userCredential.getUserId());
        return VerificationResponse.builder()
                .status(true)
                .message("OTP verified successfully")
                .build();
    }

    private void otpValidation(final UUID userId, final String email, final String otp, final String storedHashedOtp, final OtpType type) {
        if (storedHashedOtp == null) {
            log.warn("Expired OTP verification attempt for userId: {}", userId);
            throw new OTPExpired("OTP expired. Please request a new one.");
        }
        if (!passwordEncoder.matches(otp, storedHashedOtp)) {
            redisOtpStore.handleInvalidOtp
                    (userId, email, type);
            log.warn("Invalid OTP verification attempt for userId: {}", userId);
            throw new OTPValidation("Invalid OTP");
        }
        redisOtpStore.markVerified(userId, email, type);
        redisOtpStore.clearOtpOnly(userId, email, type);
    }

    @Override
    @Transactional
    public void resendVerificationOtp(final ResendOtpRequest request) {
        final String email = request.email().trim().toLowerCase();
        final OtpType type = OtpType.REGISTRATION;
        log.info("Processing OTP resend request for newEmail: {}", email);
        final UserDetail userDetail = findUserByEmail(email);
        validateAccountNotVerified(userDetail);
        redisOtpStore.validateRequest(null, userDetail.getEmail(), type);
        sendOtp(userDetail, type);
        log.info("Verification OTP resent successfully to newEmail: {}", email);
    }

    private void validateAccountNotVerified(final UserDetail userDetail) {
        if (userDetail.isEnabled()) {
            log.warn("Account already verified for newEmail: {}", userDetail.getEmail());
            throw new AccountVerification("Account already verified");
        }
    }

    private void sendOtp(final UserDetail saved, final OtpType type) {
        final String otp = otpGeneration.generateOtp();
        final String hashOtp = passwordEncoder.encode(otp);
        redisOtpStore.storeOtp(null, saved.getEmail(), hashOtp, type);
        log.info("Sending Email.....");
        final OtpEvent data = OtpEvent.builder()
                .eventId(Generate.generateEventId())
                .email(saved.getEmail())
                .otp(otp)
                .build();
        eventPublisherService.sendVerificationOtp(data);
    }

    @Override
    @Transactional
    public void requestCurrentEmailVerification(final VerifyEmail request) {
        final UUID userId = SecurityContext.getCurrentUserId();
        final String email = request.email();
        final OtpType type = OtpType.VERIFY_EMAIL;
        verifyUserHasEmail(userId, email);
        redisOtpStore.validateRequest(userId, email, type);
        final String otp = otpGeneration.generateOtp();
        final String hashedOtp = passwordEncoder.encode(otp);
        redisOtpStore.storeOtp(userId, email, hashedOtp, type);
        final OtpEvent data = OtpEvent.builder()
                .eventId(Generate.generateEventId())
                .email(email)
                .otp(otp)
                .build();
        eventPublisherService.sendEmailVerifyData(data);
    }

    @Override
    @Transactional
    public VerificationResponse confirmCurrentEmailVerification(final VerifyOtp request) {
        final String email = request.email();
        final OtpType type = OtpType.VERIFY_EMAIL;
        final UUID userId = SecurityContext.getCurrentUserId();
        verifyUserHasEmail(userId, email);
        final String storedHashedOtp = redisOtpStore.getOtp(userId, email, type);
        otpValidation(userId, email, request.otp(), storedHashedOtp, type);
        final boolean verified = redisOtpStore.isVerified(userId, email, type);
        if (!verified) {
            log.warn("Attempted without OTP verification for current email for userId: {}", userId);
            throw new OTPValidation("OTP verification required");
        }
        redisOtpStore.clearAll(userId, email, type);
        return VerificationResponse.builder()
                .status(true)
                .message("Current email has been verified")
                .build();
    }

    @Override
    @Transactional
    public void requestEmailChange(final EmailRequest request) {
        final String newEmail = request.newEmail();
        final OtpType type = OtpType.EMAIL_CHANGE;
        final UUID userId = SecurityContext.getCurrentUserId();
        final UserDetail userDetail = findUserByUserId(userId);
        if (userDetail.getEmail().equalsIgnoreCase(newEmail)) {
            log.warn("New newEmail cannot be same as current newEmail: {}", newEmail);
            throw new EmailAlreadyExists("New newEmail cannot be same as current newEmail");
        }
        if (userRepository.existsByEmail(newEmail)) {
            log.warn("Email already in use: {}", newEmail);
            throw new EmailAlreadyExists("Email already in use");
        }
        redisOtpStore.validateRequest(userId, newEmail, type);
        final String otp = otpGeneration.generateOtp();
        final String hashedOtp = passwordEncoder.encode(otp);
        redisOtpStore.storeOtp(userId, newEmail, hashedOtp, type);
        OtpEvent data = OtpEvent.builder()
                .eventId(Generate.generateEventId())
                .email(newEmail)
                .otp(otp)
                .build();
        eventPublisherService.sendEmailChangeOtp(data);
        log.info("Email change OTP sent successfully for userId: {}", userId);
    }

    @Override
    @Transactional
    public VerificationResponse confirmEmailChange(final VerifyOtp request) {
        final String email = request.email().trim().toLowerCase();
        final OtpType type = OtpType.EMAIL_CHANGE;
        final UUID userId = SecurityContext.getCurrentUserId();
        final UserDetail userDetail = findUserByUserId(userId);
        final String oldEmail = userDetail.getEmail();
        final String storedHashedOtp = redisOtpStore.getOtp(userId, email, type);
        if (storedHashedOtp == null) {
            log.warn("Expired email change OTP verification attempt for userId: {}", userId);
            throw new OTPExpired("OTP expired. Please request a new one.");
        }
        if (!passwordEncoder.matches(request.otp(), storedHashedOtp)) {
            redisOtpStore.handleInvalidOtp(userId, email, type);
            log.warn("Invalid newEmail change OTP verification attempt for userId: {}", userId);
            throw new OTPValidation("Invalid OTP");
        }
        userDetail.setEmail(email);
        redisOtpStore.markVerified(userId, email, type);
        redisOtpStore.clearOtpOnly(userId, email, type);
        redisOtpStore.clearAll(userDetail.getUserId(), email, type);
        log.info("Email change OTP verified successfully for userId: {}", userId);
        final SecurityEvent data = SecurityEvent.builder()
                .eventId(Generate.generateEventId())
                .newMail(email)
                .oldMail(oldEmail)
                .timestamp(Instant.now())
                .build();
        eventPublisherService.sendSecurityAlertToOldEmail(data);
        return VerificationResponse.builder()
                .status(true)
                .message("Email changed successfully")
                .build();
    }

    private UserDetail findUserByUserId(final UUID userId) {
        return userRepository.findByUserId(userId)
                .orElseThrow(() -> {
                    log.warn("User not found with id: {}", userId);
                    return new UserDetailNotFound("User not found");
                });
    }

    private void verifyUserHasEmail(final UUID userId, final String email) {
        if (!userRepository.existsByUserIdAndEmail(userId, email)) {
            log.warn("Email id: {}, does not belong to current user with id: {}", email, userId);
            throw new Unauthorized("Email does not belong to current user");
        }
    }

    private UserDetail findUserByEmail(final String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("User's newEmail not found: {}", email);
                    return new EmailNotFound("User's newEmail not found");
                });
    }

    private void validateOtp(final String requestOtp, final String email, final OtpType type) {
        final String storedOtp = redisOtpStore.getOtp(null, email, type);
        if (storedOtp == null) {
            log.warn("OTP expired for newEmail: {}", email);
            throw new OTPExpired("OTP expired. Please request a new one.");
        }
        if (!passwordEncoder.matches(requestOtp, storedOtp)) {
            redisOtpStore.handleInvalidOtp(null, email, type);
            log.warn("Invalid OTP attempt for newEmail: {}", email);
            throw new OTPValidation("Invalid OTP");
        }
        redisOtpStore.markVerified(null, email, type);
    }

    private void activateAccount(final UserDetail userDetail) {
        if (!userDetail.isEnabled()) {
            userDetail.setEnabled(true);
            userDetail.setScheduledDeletionAt(null);
            log.info("User account activated: {}", userDetail.getEmail());
        }
    }
}
