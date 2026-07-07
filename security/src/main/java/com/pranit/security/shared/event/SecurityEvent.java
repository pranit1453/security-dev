package com.pranit.security.shared.event;

import lombok.Builder;

@Builder
public record SecurityEvent(
        String eventId,
        String newMail,
        String oldMail
) {
}
