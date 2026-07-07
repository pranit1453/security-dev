package com.pranit.security.shared.event;

import lombok.Builder;

@Builder
public record OtpEvent(
        String eventId,
        String email,
        String otp
) {
}
