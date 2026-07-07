package com.pranit.security.shared.event;

import com.pranit.security.shared.constants.OtpType;
import lombok.Builder;

@Builder
public record OtpEvent(
        String eventId,
        String email,
        String otp,
        OtpType type
) {
}
