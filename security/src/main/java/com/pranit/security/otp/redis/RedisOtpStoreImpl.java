package com.pranit.security.otp.redis;


import com.pranit.security.shared.constants.OtpType;
import com.pranit.security.shared.exception.OTPBlock;
import com.pranit.security.shared.exception.OTPResend;
import com.pranit.security.shared.redis.RedisOtpStore;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RedisOtpStoreImpl implements RedisOtpStore {

    private static final int MAX_REQUESTS = 3;
    private static final int MAX_VERIFY_ATTEMPTS = 3;
    private static final long OTP_TTL = 180; // 3 min
    private static final long RESEND_TTL = 60; // 1 min
    private static final long BLOCK_TTL = 600; // 10 min
    private static final long VERIFIED_TTL = 600; // 10 min

    private final StringRedisTemplate redisTemplate;

    @Override
    public void validateRequest(UUID userId, String email, OtpType type) {
        String id = identifier(userId, email);
        String blockKey = key("otp:block", type, id);
        String resendKey = key("otp:resend", type, id);
        String reqKey = key("otp:req", type, id);

        //  BLOCK CHECK (10 min)
        Long blockTtl = redisTemplate.getExpire(blockKey);
        if (blockTtl != null && blockTtl > 0) {
            throw new OTPBlock("Blocked. Try again after " + toMinutes(blockTtl) + " minute(s)");
        }
        // RESEND CHECK (1 min)
        Long resendTtl = redisTemplate.getExpire(resendKey);
        if (resendTtl != null && resendTtl > 0) {
            throw new OTPResend("Please wait " + toMinutes(resendTtl) + " minute(s) before requesting again");
        }

        // increment request count
        Long count = redisTemplate.opsForValue().increment(reqKey);
        if (count != null && count == 1) {
            redisTemplate.expire(reqKey, Duration.ofSeconds(BLOCK_TTL));
        }

        // block if exceed
        if (count != null && count > MAX_REQUESTS) {
            redisTemplate.opsForValue().set(blockKey, "BLOCKED", Duration.ofSeconds(BLOCK_TTL));
            throw new OTPBlock("Too many OTP requests. Blocked for " + (BLOCK_TTL / 60) + " minutes");
        }

        // SET RESEND LOCK (1 min)
        redisTemplate.opsForValue().set(resendKey, "LOCK", Duration.ofSeconds(RESEND_TTL));
    }

    private String identifier(UUID userId, String email) {
        return (userId != null)
                ? userId + ":" + email
                : email;
    }

    private String key(String prefix, OtpType type, String identifier) {
        return prefix + ":" + type + ":" + identifier;
    }

    private long toMinutes(Long ttl) {
        if (ttl == null || ttl <= 0) return 1;
        return (ttl + 59) / 60;
    }

    @Override
    public void storeOtp(UUID userId, String email, String otp, OtpType type) {
        String id = identifier(userId, email);
        redisTemplate.opsForValue().set(
                key("otp", type, id),
                otp,
                Duration.ofSeconds(OTP_TTL)
        );
    }

    @Override
    public String getOtp(UUID userId, String email, OtpType type) {
        String id = identifier(userId, email);
        return redisTemplate.opsForValue().get(key("otp", type, id));
    }

    @Override
    public void handleInvalidOtp(UUID userId, String email, OtpType type) {
        String id = identifier(userId, email);
        String attemptKey = key("otp:attempt", type, id);
        String blockKey = key("otp:block", type, id);

        Long attempt = redisTemplate.opsForValue().increment(attemptKey);

        if (attempt != null && attempt == 1) {
            redisTemplate.expire(attemptKey, Duration.ofSeconds(BLOCK_TTL));
        }

        if (attempt != null && attempt >= MAX_VERIFY_ATTEMPTS) {
            redisTemplate.opsForValue().set(
                    blockKey,
                    "BLOCKED",
                    Duration.ofSeconds(BLOCK_TTL)
            );
            throw new OTPBlock("Too many wrong attempts. Blocked for " + (BLOCK_TTL / 60) + " minutes");
        }
    }

    @Override
    public void markVerified(UUID userId, String email, OtpType type) {
        String id = identifier(userId, email);

        redisTemplate.opsForValue().set(
                key("otp:verified", type, id),
                "VERIFIED",
                Duration.ofSeconds(VERIFIED_TTL)
        );
    }

    @Override
    public boolean isVerified(UUID userId, String email, OtpType type) {
        String id = identifier(userId, email);
        String value = redisTemplate.opsForValue().get(key("otp:verified", type, id));
        return "VERIFIED".equals(value);
    }

    @Override
    public void clearOtpOnly(UUID userId, String email, OtpType type) {
        String id = identifier(userId, email);

        redisTemplate.delete(List.of(
                key("otp", type, id),
                key("otp:attempt", type, id)
        ));
    }

    @Override
    public void clearAll(UUID userId, String email, OtpType type) {
        String id = identifier(userId, email);

        redisTemplate.delete(List.of(
                key("otp", type, id),
                key("otp:req", type, id),
                key("otp:resend", type, id),
                key("otp:block", type, id),
                key("otp:attempt", type, id),
                key("otp:verified", type, id)
        ));
    }
}
