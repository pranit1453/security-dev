package com.pranit.security.authentication.dto;

import lombok.Builder;

@Builder
public record ForgotPasswordResponse(
        boolean status,
        String message
) {
}
