package com.pranit.security.authentication.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record VerifyOtp(
        @Email(message = "Invalid newEmail format!!!")
        @NotBlank(message = "Email is mandatory!!!")
        String email,
        @NotBlank(message = "Otp is required!!!")
        String otp
) {
}
