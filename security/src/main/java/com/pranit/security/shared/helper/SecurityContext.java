package com.pranit.security.shared.helper;

import com.pranit.security.authentication.entity.UserDetail;
import com.pranit.security.shared.exception.Unauthorized;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.UUID;

@Slf4j
public final class SecurityContext {

    private SecurityContext() {
    }

    public static UUID getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null ||
            !authentication.isAuthenticated() ||
            authentication instanceof AnonymousAuthenticationToken) {
            log.warn("User is not authenticated: {}", authentication);
            throw new Unauthorized("User not authenticated");
        }

        Object principal = authentication.getPrincipal();

        if (!(principal instanceof UserDetail userDetail)) {
            log.warn("Invalid authentication principal: {}", principal);
            throw new Unauthorized("Invalid authentication principal");
        }

        UUID userId = userDetail.getUserId();

        if (userId == null) throw new Unauthorized("Authenticated user ID not found");

        return userId;
    }
}
