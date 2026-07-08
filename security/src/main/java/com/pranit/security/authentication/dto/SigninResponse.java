package com.pranit.security.authentication.dto;

import lombok.Builder;

import java.util.Set;

@Builder
public record SigninResponse(
        String username,
        Set<String> roles,
        Set<String> permissions
) {
}
