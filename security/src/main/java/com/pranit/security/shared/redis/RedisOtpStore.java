package com.pranit.security.shared.redis;


import com.pranit.security.shared.constants.OtpType;

import java.util.UUID;

public interface RedisOtpStore {

    void validateRequest(UUID userId, String email, OtpType type);

    void storeOtp(UUID userId, String email, String otp, OtpType type);

    String getOtp(UUID userId, String email, OtpType type);

    void handleInvalidOtp(UUID userId, String email, OtpType type);

    void markVerified(UUID userId, String email, OtpType type);

    boolean isVerified(UUID userId, String email, OtpType type);

    void clearOtpOnly(UUID userId, String email, OtpType type);

    void clearAll(UUID userId, String email, OtpType type);
}
