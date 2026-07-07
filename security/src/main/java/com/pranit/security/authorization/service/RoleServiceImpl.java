package com.pranit.security.authorization.service;

import com.pranit.security.authorization.api.RoleService;
import com.pranit.security.authorization.entity.RoleDetail;
import com.pranit.security.authorization.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RoleServiceImpl implements RoleService {

    private final RoleRepository roleRepository;

    @Override
    public Optional<RoleDetail> findByRoleNameWithPermissions(String defaultRole) {
        return roleRepository.findByRoleNameWithPermissions(defaultRole);
    }
}
