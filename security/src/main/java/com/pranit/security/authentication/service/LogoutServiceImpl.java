package com.pranit.security.authentication.service;

import com.pranit.security.authentication.jwt.service.CookieService;
import com.pranit.security.authentication.jwt.service.ExtractClaim;
import com.pranit.security.authentication.repository.RefreshTokenRepository;
import com.pranit.security.shared.properties.CookieProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public final class LogoutServiceImpl implements LogoutService {

    private static final String BEARER = "Bearer ";
    private final ExtractClaim extractClaim;
    private final RefreshTokenRepository refreshTokenRepository;
    private final CookieService cookieService;
    private final CookieProperties cookieProperties;

    @Override
    public Optional<String> readRefreshTokenFromRequest(HttpServletRequest request) {
        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorizationHeader != null && authorizationHeader.startsWith(BEARER)) {
            String token = authorizationHeader.substring(7).trim();
            Claims claims = extractClaim.validateAndParseToken(token);
            if (!claims.isEmpty()) {
                try {
                    if (extractClaim.isRefreshToken(claims)) {
                        log.debug("Refresh token extracted successfully from request");
                        return Optional.of(token);
                    }
                    log.warn("Provided token is not a refresh token");
                } catch (Exception e) {
                    log.warn("Invalid refresh token received during logout");
                }
            }
        }
        log.debug("No refresh token found in request");
        return Optional.empty();
    }

    @Override
    public void revokedRefreshToken(String token) {
        try {
            Claims claims = extractClaim.validateAndParseToken(token);
            if (!extractClaim.isRefreshToken(claims)) {
                log.warn("Attempted to revoke non-refresh token");
                return;
            }
            final String jti = extractClaim.getJtiFromRefreshToken(claims);
            refreshTokenRepository.findByJti(jti)
                    .ifPresent(refreshToken -> {
                        if (!refreshToken.isRevoked()) {
                            refreshToken.setRevoked(true);
                            log.info("Refresh token revoked successfully for jti: {}", jti);
                        } else {
                            log.debug("Refresh token already revoked for jti: {}", jti);
                        }
                    });
        } catch (JwtException ex) {
            log.warn("Invalid refresh token received for revocation");
        }
    }

    @Override
    public Optional<String> readAccessTokenFromRequest(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return Optional.empty();
        return Arrays.stream(cookies)
                .filter(cookie -> cookieProperties.name().accessTokenName().equals(cookie.getName()))
                .map(Cookie::getValue)
                .filter(value -> value != null && !value.isBlank())
                .findFirst();
    }

    @Override
    public void revokedAccessToken(String token) {
        try {
            Claims claims = extractClaim.validateAndParseToken(token);
            final UUID userId = extractClaim.getUserIdFromAccessToken(claims);
            refreshTokenRepository.revokeAllByUserId(userId);
            log.info("Access session revoked successfully for userId: {}", userId);
        } catch (JwtException ex) {
            log.warn("Invalid access token received for revocation");
        }
    }

    @Override
    public void clearResponse(HttpServletResponse response) {
        cookieService.clearAccessTokenCookie(response);
        cookieService.clearRefreshTokenCookie(response);
        cookieService.addNoStoreHeaders(response);
        SecurityContextHolder.clearContext();
    }
}
