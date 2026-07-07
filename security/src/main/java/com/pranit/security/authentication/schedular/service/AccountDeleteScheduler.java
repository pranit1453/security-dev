package com.pranit.security.authentication.schedular.service;

import com.pranit.security.authentication.repository.RefreshTokenRepository;
import com.pranit.security.authentication.repository.UserRepository;
import com.pranit.security.authentication.service.AccountDeletionService;
import com.pranit.security.shared.redis.RedisTokenStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AccountDeleteScheduler {

    private final AccountDeletionService accountDeletionService;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final RedisTokenStore redisTokenStore;

    @Scheduled(cron = "0 0 2 * * *", zone = "Asia/Kolkata")
    @Transactional
    public void permanentlyDeleteUsers() {
        final Instant now = Instant.now();
        final List<UUID> userIds = userRepository.findAllIdsScheduleForPermanentDeletion(now);
        if (userIds.isEmpty()) {
            log.info("No accounts scheduled for permanent deletion");
            return;
        }
        log.info("Permanent deletion for {} users", userIds.size());
        redisTokenStore.invalidateUserSession(userIds);
        refreshTokenRepository.deleteAllByUserIds(userIds);
        userRepository.deleteUserRoles(userIds);
        userRepository.deleteAllByUserIds(userIds);
        log.info("Permanent account deletion completed for {} users", userIds.size());
    }
}
