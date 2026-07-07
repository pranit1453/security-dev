package com.pranit.security.authentication.service;

import com.pranit.security.authentication.entity.UserDetail;
import com.pranit.security.authentication.exception.UserDetailNotFound;
import com.pranit.security.authentication.repository.RefreshTokenRepository;
import com.pranit.security.authentication.repository.UserRepository;
import com.pranit.security.shared.redis.RedisTokenStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AccountDeletionServiceImpl implements AccountDeletionService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final RedisTokenStore redisTokenStore;

    @Override
    @Transactional
    public void deleteUserAccountPermanently(final UUID userId) {

        UserDetail userDetail = findUserByUserId(userId);
        userDetail.getRoles().clear();
        refreshTokenRepository.revokeAllByUserId(userId);
        redisTokenStore.invalidateUserSession(userId);
        userRepository.delete(userDetail);
        log.info("User account permanently deleted for userId: {}", userId);
    }

    private UserDetail findUserByUserId(final UUID userId) {
        return userRepository.findByUserId(userId)
                .orElseThrow(() -> {
                    log.warn("User not found with userId: {}", userId);
                    return new UserDetailNotFound("User not found");
                });
    }
}
