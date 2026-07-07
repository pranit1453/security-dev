package com.pranit.security.authentication.service;

import com.pranit.security.authentication.dto.TokenResponse;
import com.pranit.security.authentication.entity.RefreshToken;
import com.pranit.security.authentication.entity.UserDetail;
import com.pranit.security.authentication.exception.TokenExpired;
import com.pranit.security.authentication.exception.TokenOwner;
import com.pranit.security.authentication.jwt.service.CookieService;
import com.pranit.security.authentication.jwt.service.ExtractClaim;
import com.pranit.security.authentication.jwt.service.GenerateToken;
import com.pranit.security.authentication.repository.RefreshTokenRepository;
import com.pranit.security.shared.exception.Unauthorized;
import com.pranit.security.shared.helper.Generate;
import com.pranit.security.shared.properties.CookieProperties;
import com.pranit.security.shared.properties.TokenProperties;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {

    private final GenerateToken generateToken;
    private final RefreshTokenRepository refreshTokenRepository;
    private final ExtractClaim extractClaim;
    private final CookieService cookieService;
    private final CookieProperties cookieProperties;
    private final TokenProperties tokenProperties;

    @Override
    public Optional<String> readRefreshTokenFromRequest(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return Optional.empty();
        return Arrays.stream(cookies)
                .filter(cookie -> cookieProperties.name().refreshTokenName().equals(cookie.getName()))
                .map(Cookie::getValue)
                .filter(value -> value != null && !value.isBlank())
                .findFirst();
    }

    @Override
    public TokenResponse generateNewRefreshToken(String refreshToken, HttpServletResponse response) {

        Claims claims = extractClaim.validateAndParseToken(refreshToken);

        if (!extractClaim.isRefreshToken(claims)) {
            log.warn("Invalid refresh token: {}", refreshToken);
            throw new Unauthorized("Invalid token");
        }
        String jti = extractClaim.getJtiFromRefreshToken(claims);
        log.debug("JTI for new Refresh token is {}", jti);
        UUID userId = extractClaim.getUserIdFromAccessToken(claims);
        log.debug("User ID is {}", userId);
        RefreshToken token = refreshTokenRepository.findByJti(jti)
                .orElseThrow(() -> new Unauthorized("Invalid token"));

        if (token.isRevoked()) {
            refreshTokenRepository.revokeAllByUserId(token.getUserDetail().getUserId());
            log.warn("Refresh token {} reused detected", token);
            throw new Unauthorized("Token reuse detected");
        }

        if (token.getExpiresAt().isBefore(Instant.now())) {
            log.warn("Refresh token {} expired", token);
            throw new TokenExpired("Expired token");
        }
        if (!token.getUserDetail().getUserId().equals(userId)) {
            throw new TokenOwner("Token not belong to user");
        }
        token.setRevoked(true);
        String newJti = Generate.generateJti();
        token.setReplacedBy(newJti);
        refreshTokenRepository.save(token);

        UserDetail user = token.getUserDetail();
        log.debug("Refresh token for user: {}", user);
        var newRT = RefreshToken.builder()
                .jti(newJti)
                .userDetail(user)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(tokenProperties.refreshToken().expiration())).revoked(false)
                .build();

        refreshTokenRepository.save(newRT);
        String sesisonId = Generate.generateSessionId();
        String newAccessToken = generateToken.generateAccessToken(user, sesisonId);
        log.debug("New Access Token: {}", newAccessToken);
        String newRefreshToken = generateToken.generateRefreshToken(user, newJti, sesisonId);
        log.debug("New Refresh Token: {}", newRefreshToken);
        cookieService.attachAccessTokenCookie(response, newAccessToken, Duration.ofSeconds(tokenProperties.accessToken().expiration()));
        cookieService.attachRefreshTokenCookie(response, newRefreshToken, Duration.ofSeconds(tokenProperties.refreshToken().expiration()));
        cookieService.addNoStoreHeaders(response);
        return TokenResponse.builder()
                .message("Token is refreshed......")
                .build();
    }
}
