package com.pranit.security.authentication.service;

import com.pranit.security.authentication.dto.ChangeForgotPasswordRequest;
import com.pranit.security.authentication.dto.ChangePasswordRequest;
import com.pranit.security.authentication.dto.ForgotPasswordEmail;
import com.pranit.security.authentication.dto.ForgotPasswordResponse;
import com.pranit.security.authentication.dto.PasswordRequest;
import com.pranit.security.authentication.entity.UserDetail;
import com.pranit.security.authentication.exception.PasswordNotMatching;
import com.pranit.security.authentication.exception.PasswordValidation;
import com.pranit.security.authentication.exception.UserDetailNotFound;
import com.pranit.security.authentication.jwt.service.CookieService;
import com.pranit.security.authentication.repository.RefreshTokenRepository;
import com.pranit.security.authentication.repository.UserRepository;
import com.pranit.security.otp.api.OtpGeneration;
import com.pranit.security.shared.constants.OtpType;
import com.pranit.security.shared.event.OtpEvent;
import com.pranit.security.shared.exception.OTPValidation;
import com.pranit.security.shared.helper.Generate;
import com.pranit.security.shared.helper.SecurityContext;
import com.pranit.security.shared.redis.RedisOtpStore;
import com.pranit.security.shared.redis.RedisTokenStore;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordServiceImpl implements PasswordService {

    private final UserRepository userRepository;
    private final RedisOtpStore redisOtpStore;
    private final PasswordEncoder passwordEncoder;
    private final EventPublisherService eventPublisherService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final RedisTokenStore redisTokenStore;
    private final CookieService cookieService;
    private final OtpGeneration otpGeneration;

    @Override
    @Transactional
    public void requestPasswordReset(final ForgotPasswordEmail request) {
        final String email = request.email();
        final OtpType type = OtpType.PASSWORD_CHANGE;
        userRepository.findByEmail(email)
                .ifPresent(user -> {
                    redisOtpStore.validateRequest(user.getUserId(), user.getEmail(), type);
                    final String otp = otpGeneration.generateOtp();
                    final String hashedOtp = passwordEncoder.encode(otp);
                    redisOtpStore.storeOtp(user.getUserId(), user.getEmail(), hashedOtp, type);
                    OtpEvent data = OtpEvent.builder()
                            .eventId(Generate.generateEventId())
                            .email(user.getEmail())
                            .otp(otp)
                            .build();
                    eventPublisherService.sendPasswordChangeOtp(data);
                    log.info("Forgot password OTP sent successfully for userId: {}", user.getUserId());
                });
    }

    @Override
    @Transactional
    public ForgotPasswordResponse resetPassword(final ChangeForgotPasswordRequest request) {
        validatePasswordMatch(request.passwordRequest());
        final String email = request.email().trim().toLowerCase();
        final OtpType otpType = OtpType.PASSWORD_CHANGE;
        final UserDetail user = findUserByEmail(email);
        final boolean verified = redisOtpStore.isVerified(user.getUserId(), email, otpType);
        if (!verified) {
            log.warn("Password change attempted without OTP verification for userId: {}", user.getUserId());
            throw new OTPValidation("OTP verification required");
        }
        if (passwordEncoder.matches(request.passwordRequest().password(), user.getPassword())) {
            log.warn("New password matches existing password for userId: {}", user.getUserId());
            throw new PasswordValidation("New password cannot be same as old password");
        }
        user.setPassword(passwordEncoder.encode(request.passwordRequest().password()));
        redisOtpStore.clearAll(user.getUserId(), email, otpType);
        invalidateUserSession(user.getUserId());
        log.info("Forgot password reset completed successfully for userId: {}", user.getUserId());
        return ForgotPasswordResponse.builder()
                .status(true)
                .message("Password changed successfully")
                .build();
    }

    private void validatePasswordMatch(final PasswordRequest request) {
        if (!request.password().equals(request.confirmPassword())) {
            log.warn("Password and confirm password do not match");
            throw new PasswordNotMatching("Password and confirm password do not match");
        }
    }

    private UserDetail findUserByEmail(final String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("User with newEmail {} not found", email);
                    return new UserDetailNotFound("User not found");
                });
    }

    private void invalidateUserSession(final UUID userId) {
        redisTokenStore.invalidateUserSession(userId);
        refreshTokenRepository.revokeAllByUserId(userId);
        log.info("User session invalidated for userId: {}", userId);
    }

    @Override
    @Transactional
    public void changePassword(final ChangePasswordRequest request, final HttpServletResponse response) {
        final UUID userId = SecurityContext.getCurrentUserId();
        final UserDetail userData = userRepository.findByUserId(userId)
                .orElseThrow(() -> {
                    log.warn("User credentials not found for userId: {}", userId);
                    return new UserDetailNotFound("User credentials not found");
                });
        if (!passwordEncoder.matches(request.oldPassword(), userData.getPassword())) {
            log.warn("Old Password is incorrect");
            throw new PasswordNotMatching("Old Password Do Not Match");
        }
        if (!request.newPassword().equals(request.confirmPassword())) {
            log.warn("New Password Do Not Match with Confirm Password");
            throw new PasswordNotMatching("Passwords do not match");
        }
        if (passwordEncoder.matches(request.newPassword(), userData.getPassword())) {
            log.warn("New Password must be different from old password");
            throw new PasswordValidation("New Password must be different from old password");
        }
        userData.setPassword(passwordEncoder.encode(request.newPassword()));
        final UserDetail save = userRepository.save(userData);
        log.info("Change password for userId: {}", save.getUserId());
        invalidateUserSession(save.getUserId());
        cookieService.clearAccessTokenCookie(response);
        cookieService.clearRefreshTokenCookie(response);
        cookieService.addNoStoreHeaders(response);
    }
}
