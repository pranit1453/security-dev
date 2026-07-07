package com.pranit.security.authentication.oauth2.service;

import com.pranit.security.authentication.entity.UserDetail;
import com.pranit.security.authentication.exception.RoleNotFound;
import com.pranit.security.authentication.oauth2.model.OAuth2UserInfo;
import com.pranit.security.authentication.profile.entity.UserProfile;
import com.pranit.security.authentication.repository.UserRepository;
import com.pranit.security.authorization.api.RoleService;
import com.pranit.security.authorization.entity.RoleDetail;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class OAuth2UserProvisioningService {
    private static final String DEFAULT_ROLE = "USER";
    private final UserRepository userRepository;
    private final RoleService roleService;

    public UserDetail provisionUserCredential(final OAuth2UserInfo info) {
        log.debug("Checking existing OAuth2 user with provider: {}", info.provider());
        return userRepository.findByEmailWithRoles(info.email())
                .map(existingUser -> {
                    log.info("Existing OAuth2 user authenticated. userId: {}, provider: {}",
                            existingUser.getUserId(), info.provider());
                    return existingUser;
                })
                .orElseGet(() -> createUser(info));
    }

    private UserDetail createUser(final OAuth2UserInfo info) {
        log.info("Provisioning new OAuth2 user. provider: {}", info.provider());
        RoleDetail defaultRole = roleService.findByRoleNameWithPermissions(DEFAULT_ROLE)
                .orElseThrow(() -> {
                    log.warn("Default role not found during OAuth2 provisioning. role: {}",
                            DEFAULT_ROLE);
                    return new RoleNotFound("Role not found");
                });
        UserDetail detail = UserDetail.builder()
                .email(info.email())
                .username(info.username())
                .oauth2Id(info.oauth2Id())
                .provider(info.provider())
                .enabled(true)
                .build();
        detail.setRoles(Set.of(defaultRole));
        UserProfile profile = UserProfile.builder()
                .firstName(info.firstName())
                .lastName(info.lastName())
                .build();
        detail.setUserProfile(profile);
        UserDetail savedUser = userRepository.save(detail);
        log.info("OAuth2 user provisioned successfully. userId: {}, provider: {}, assignedRole: {}",
                savedUser.getUserId(), info.provider(), DEFAULT_ROLE);
        return savedUser;
    }
}
