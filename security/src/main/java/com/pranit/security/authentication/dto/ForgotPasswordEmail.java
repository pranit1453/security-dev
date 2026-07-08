package com.pranit.security.authentication.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record ForgotPasswordEmail(
        @NotBlank(message = "Email is required")
        @Email(message = "Invalid newEmail format")
        String email
) {
}
