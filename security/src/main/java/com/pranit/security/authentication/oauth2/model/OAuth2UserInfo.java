package com.pranit.security.authentication.oauth2.model;

import com.pranit.security.authentication.constants.Provider;
import lombok.Builder;

@Builder
public record OAuth2UserInfo(
        String oauth2Id,
        String email,
        String username,
        String firstName,
        String lastName,
        Provider provider
) {
}

