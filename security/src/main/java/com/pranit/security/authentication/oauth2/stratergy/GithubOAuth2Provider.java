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
public class GithubOAuth2Provider implements OAuth2Provider {
    @Override
    public Provider getProvider() {
        return Provider.GITHUB;
    }

    @Override
    public OAuth2UserInfo extractUserInfo(OAuth2User user) {
        log.debug("Extracting OAuth2 user information. provider: {}", Provider.GITHUB);
        String githubId = Optional.ofNullable(user.getAttribute("id"))
                .map(Object::toString)
                .orElseThrow(() -> {
                    log.warn("Required OAuth2 attribute missing. provider: {}, attribute=id", Provider.GITHUB);
                    return new OAuth2Authentication("GitHub user id not found");
                });
        String name = user.getAttribute("login");

        String email = Optional.ofNullable(user.getAttribute("newEmail"))
                .orElse(name + "@github.com").toString();
        log.debug("OAuth2 user information extracted successfully. provider: {}", Provider.GITHUB);
        return OAuth2UserInfo.builder()
                .oauth2Id(githubId)
                .email(email)
                .username(name)
                .firstName(name)
                .lastName("")
                .provider(Provider.GITHUB)
                .build();
    }
}
