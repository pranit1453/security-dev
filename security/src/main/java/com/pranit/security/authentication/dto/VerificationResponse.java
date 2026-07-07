package com.pranit.security.authentication.dto;

import lombok.Builder;

@Builder
public record VerificationResponse(
        boolean status,
        String message
) {
}
