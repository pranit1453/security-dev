package com.pranit.security.authorization.api;

import com.pranit.security.authorization.entity.RoleDetail;

import java.util.Optional;

public interface RoleService {
    Optional<RoleDetail> findByRoleNameWithPermissions(String defaultRole);
}
