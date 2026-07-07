package com.pranit.security.authentication.service;

import com.pranit.security.authentication.constants.Provider;
import com.pranit.security.authentication.dto.RegistrationRequest;
import com.pranit.security.authentication.dto.SignupResponse;
import com.pranit.security.authentication.entity.UserDetail;
import com.pranit.security.authentication.exception.EmailAlreadyExists;
import com.pranit.security.authentication.exception.PasswordNotMatching;
import com.pranit.security.authentication.exception.RoleNotFound;
import com.pranit.security.authentication.exception.UsernameAlreadyExists;
import com.pranit.security.authentication.profile.entity.UserProfile;
import com.pranit.security.authentication.repository.UserRepository;
import com.pranit.security.authorization.api.RoleService;
import com.pranit.security.authorization.entity.RoleDetail;
import com.pranit.security.otp.api.OtpGeneration;
import com.pranit.security.shared.constants.OtpType;
import com.pranit.security.shared.event.OtpEvent;
import com.pranit.security.shared.helper.Generate;
import com.pranit.security.shared.redis.RedisOtpStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class RegistrationServiceImpl implements RegistrationService {

    private static final String USER_ROLE = "USER";
    private static final String ADMIN_ROLE = "ADMIN";
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RoleService roleService;
    private final EventPublisherService eventPublisherService;
    private final RedisOtpStore redisOtpStore;
    private final OtpGeneration otpGeneration;

    @Override
    @Transactional
    public SignupResponse createNewUserAccount(RegistrationRequest request) {
        return registerAccount(request, USER_ROLE);
    }

    @Override
    @Transactional
    public SignupResponse createNewAdminAccount(RegistrationRequest request) {
        return registerAccount(request, ADMIN_ROLE);
    }

    private SignupResponse registerAccount(final RegistrationRequest request, final String roleName) {
        validateUniqueUsernameAndEmail(request.username(), request.email());
        validatePasswordMatch(request.password(), request.confirmPassword());
        final OtpType type = OtpType.REGISTRATION;
        log.info("OTP Validation in Redis Cache: {},{}", request.email(), type);
        validateOtpRequest(request.email(), type);
        final UserDetail userDetail = buildUserCredential(request);
        userDetail.addRole(findRole(roleName));
        final UserProfile userProfile = buildUserProfile(request);
        userDetail.setUserProfile(userProfile);
        final UserDetail saved = userRepository.save(userDetail);
        log.info("New account created successfully for username: {}", saved.getUsername());
        sendOtp(saved, type);
        return SignupResponse.builder()
                .message("Check email to verify account and activate it.")
                .build();
    }

    private void validateUniqueUsernameAndEmail(final String username, final String email) {
        if (userRepository.existsByUsername(username)) {
            log.warn("Username already taken: {}", username);
            throw new UsernameAlreadyExists("Username already taken");
        }

        if (userRepository.existsByEmail(email)) {
            log.warn("Email already taken: {}", email);
            throw new EmailAlreadyExists("Email already in use.");
        }
    }

    private void validatePasswordMatch(final String password, final String confirmPassword) {
        if (!password.equals(confirmPassword)) {
            log.warn("Password confirmation mismatch");
            throw new PasswordNotMatching("Password and confirm password do not match");
        }
    }

    private void validateOtpRequest(final String email, final OtpType type) {
        log.info("Validating OTP request for newEmail: {}", email);
        redisOtpStore.validateRequest(null, email, type);
    }

    private UserDetail buildUserCredential(final RegistrationRequest request) {
        return UserDetail.builder()
                .username(request.username())
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .oauth2Id(null)
                .provider(Provider.LOCAL)
                .enabled(false)
                .deleted(false)
                .scheduledDeletionAt(Instant.now().plus(1, ChronoUnit.DAYS))
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .build();
    }

    private RoleDetail findRole(final String roleName) {
        return roleService.findByRoleNameWithPermissions(roleName)
                .orElseThrow(() -> {
                    log.warn("Role not found with name: {}", roleName);
                    return new RoleNotFound("Role not found");
                });
    }

    private UserProfile buildUserProfile(final RegistrationRequest request) {
        return UserProfile.builder()
                .firstName(request.firstName())
                .lastName(request.lastName())
                .dob(request.dob())
                .gender(request.gender())
                .address(request.address())
                .build();
    }

    private void sendOtp(UserDetail saved, OtpType type) {
        final String otp = otpGeneration.generateOtp();
        final String hashOtp = passwordEncoder.encode(otp);
        redisOtpStore.storeOtp(null, saved.getEmail(), hashOtp, type);
        log.info("Send Email for account activation");
        OtpEvent data = OtpEvent.builder()
                .eventId(Generate.generateEventId())
                .email(saved.getEmail())
                .otp(otp)
                .build();
        eventPublisherService.sendVerificationOtp(data);
    }
}
