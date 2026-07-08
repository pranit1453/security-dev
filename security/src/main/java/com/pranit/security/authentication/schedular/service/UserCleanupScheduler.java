package com.pranit.security.authentication.schedular.service;

import com.pranit.security.authentication.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserCleanupScheduler {

    private final UserRepository userRepository;

    @Scheduled(fixedRate = 3600000)
    public void deleteUnverifiedUsers() {
        int deletedCount = userRepository.deleteExpiredUnverifiedUsers(Instant.now());
        log.info("Deleted {} UserCredentials for deletion", deletedCount);

    }
}
