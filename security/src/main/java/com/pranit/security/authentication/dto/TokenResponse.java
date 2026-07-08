package com.pranit.security.authentication.dto;

import lombok.Builder;

@Builder
public record TokenResponse(
        String message
) {
}
