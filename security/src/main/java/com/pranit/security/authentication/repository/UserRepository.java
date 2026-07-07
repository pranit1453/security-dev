package com.pranit.security.authentication.repository;

import com.pranit.security.authentication.entity.UserDetail;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<UserDetail, UUID> {

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    Optional<UserDetail> findByUserId(UUID userId);

    @EntityGraph(attributePaths = {
            "roles",
            "roles.permissions"
    })
    Optional<UserDetail> findByUsername(String username);

    @Query("""
            SELECT u.userId
            FROM UserDetail u
            WHERE u.deleted = true
            AND u.scheduledDeletionAt < :now
            """)
    List<UUID> findAllIdsScheduleForPermanentDeletion(@Param("now") Instant now);

    @Modifying
    @Query(value = """
            DELETE FROM user_roles
            WHERE user_id IN (:userIds)
            """, nativeQuery = true)
    void deleteUserRoles(List<UUID> userIds);

    @Modifying
    @Query("""
            DELETE FROM UserDetail u
            WHERE u.userId IN :userIds
            """)
    void deleteAllByUserIds(List<UUID> userIds);

    @Modifying
    @Transactional
    @Query("""
                DELETE FROM UserDetail u
                WHERE u.enabled = false
                AND u.scheduledDeletionAt < :now
            """)
    int deleteExpiredUnverifiedUsers(Instant now);

    @Query("""
                SELECT DISTINCT u
                FROM UserDetail u
                LEFT JOIN FETCH u.roles r
                LEFT JOIN FETCH r.permissions
                WHERE u.email = :email
            """)
    Optional<UserDetail> findByEmailWithRoles(String email);
}
