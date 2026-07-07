package com.pranit.security.authentication.repository;

import com.pranit.security.authentication.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Transactional
    @Query("""
            UPDATE RefreshToken rt
               SET rt.revoked = true
             WHERE rt.userDetail.userId = :userId
               AND rt.revoked = false
            """)
    void revokeAllByUserId(UUID userId);

    @Modifying
    @Transactional
    @Query("""
                DELETE FROM RefreshToken r
                WHERE r.userDetail.userId IN :userIds
            """)
    void deleteAllByUserIds(List<UUID> userIds);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Transactional
    @Query("""
            DELETE FROM RefreshToken rt
            WHERE rt.expiresAt < :now
            OR rt.revoked = true
            """)
    int deleteExpiredAndRevokedTokens(Instant now);

    Optional<RefreshToken> findByJti(String jti);
}
