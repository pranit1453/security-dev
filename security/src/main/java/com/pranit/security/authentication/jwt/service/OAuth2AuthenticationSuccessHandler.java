package com.pranit.security.authentication.jwt.service;

import com.pranit.security.authentication.entity.RefreshToken;
import com.pranit.security.authentication.entity.UserDetail;
import com.pranit.security.authentication.oauth2.service.OAuth2AuthenticationService;
import com.pranit.security.authentication.repository.RefreshTokenRepository;
import com.pranit.security.shared.helper.Generate;
import com.pranit.security.shared.properties.TokenProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NullMarked;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
@NullMarked
public class OAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final OAuth2AuthenticationService oAuth2AuthenticationService;
    private final GenerateToken generateToken;
    private final RefreshTokenRepository refreshTokenRepository;
    private final TokenProperties tokenProperties;
    private final CookieService cookieService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        log.info("In Oauth2 Authentication success Handlers");
        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        OAuth2User user = (OAuth2User) authentication.getPrincipal();
        UserDetail userDetail = oAuth2AuthenticationService.authenticate(token.getAuthorizedClientRegistrationId(), user);

        final String jti = Generate.generateJti();
        final UUID userId = userDetail.getUserId();
        if (userId != null) {
            refreshTokenRepository.revokeAllByUserId(userId);
        }
        RefreshToken rt = RefreshToken.builder()
                .jti(jti)
                .userDetail(userDetail)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(tokenProperties.refreshToken().expiration()))
                .revoked(false)
                .build();
        refreshTokenRepository.save(rt);

        final String sessionId = Generate.generateSessionId();
        final String accessToken = generateToken.generateAccessToken(userDetail, sessionId);
        final String refreshToken = generateToken.generateRefreshToken(userDetail, jti, sessionId);
        cookieService.attachAccessTokenCookie(response, accessToken, Duration.ofMinutes(tokenProperties.accessToken().expiration()));
        cookieService.attachRefreshTokenCookie(response, refreshToken, Duration.ofMinutes(tokenProperties.refreshToken().expiration()));
        cookieService.addNoStoreHeaders(response);
        String res = """
                "Login successful",
                "Access Token": %s,
                "Refresh Token: %s,
                """.formatted(accessToken, refreshToken);
        response.getWriter().write(res);

    }
}
