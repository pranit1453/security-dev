package com.pranit.security.authentication.dto;

import jakarta.validation.constraints.NotBlank;

public record ChangePasswordRequest(
        @NotBlank(message = "Old password is required")
        String oldPassword,
        @NotBlank(message = "New Password is required")
        String newPassword,
        @NotBlank(message = "Confirm password is required")
        String confirmPassword
) {
}
