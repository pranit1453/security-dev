package com.pranit.security.authentication.dto;


import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record ChangeForgotPasswordRequest(

        @Email(message = "Invalid newEmail format")
        @NotBlank(message = "Email is required")
        String email,

        PasswordRequest passwordRequest


) {
}
