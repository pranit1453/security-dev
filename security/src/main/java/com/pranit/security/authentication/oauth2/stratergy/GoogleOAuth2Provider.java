package com.pranit.security.authentication.oauth2.stratergy;

import com.pranit.security.authentication.constants.Provider;
import com.pranit.security.authentication.exception.OAuth2Authentication;
import com.pranit.security.authentication.oauth2.model.OAuth2UserInfo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class GoogleOAuth2Provider implements OAuth2Provider {

    @Override
    public Provider getProvider() {
        return Provider.GOOGLE;
    }

    @Override
    public OAuth2UserInfo extractUserInfo(OAuth2User user) {
        log.debug("Extracting OAuth2 user information. provider: {}", Provider.GOOGLE);
        String googleId = Optional.ofNullable(user.getAttribute("sub"))
                .map(String.class::cast)
                .orElseThrow(() -> {
                    log.warn("Required OAuth2 attribute missing. provider: {}, attribute: sub", Provider.GOOGLE);
                    return new OAuth2Authentication("Google subject identifier not found");
                });

        String email = Optional.ofNullable(user.getAttribute("newEmail"))
                .map(String.class::cast)
                .orElseThrow(() -> {
                    log.warn("Required OAuth2 attribute missing. provider: {}, attribute: newEmail", Provider.GOOGLE);
                    return new OAuth2Authentication("Google newEmail not found");
                });
        String name = user.getAttribute("name");
        log.debug("OAuth2 user information extracted successfully. provider: {}", Provider.GOOGLE);
        return OAuth2UserInfo.builder()
                .oauth2Id(googleId)
                .email(email)
                .username(email)
                .firstName(name)
                .lastName("")
                .provider(Provider.GOOGLE)
                .build();
    }
}
