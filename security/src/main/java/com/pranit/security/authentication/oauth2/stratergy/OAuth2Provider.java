package com.pranit.security.authentication.oauth2.stratergy;

import com.pranit.security.authentication.constants.Provider;
import com.pranit.security.authentication.oauth2.model.OAuth2UserInfo;
import org.springframework.security.oauth2.core.user.OAuth2User;

public interface OAuth2Provider {

    Provider getProvider();

    OAuth2UserInfo extractUserInfo(OAuth2User user);
}
