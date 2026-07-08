package com.pranit.security.authorization.repository;

import com.pranit.security.authorization.entity.RoleDetail;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface RoleRepository extends JpaRepository<RoleDetail, UUID> {

    @Query("""
            SELECT r
            FROM RoleDetail r
            LEFT JOIN FETCH r.permissions
            WHERE r.roleName = :roleName
            """)
    Optional<RoleDetail> findByRoleNameWithPermissions(@Param("roleName") String roleName);
}
