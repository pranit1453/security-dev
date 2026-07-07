package com.pranit.security.authentication.jwt.helper;

import com.pranit.security.authentication.jwt.service.CookieService;
import com.pranit.security.shared.properties.CookieProperties;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
@RequiredArgsConstructor
public final class CookieServiceImpl implements CookieService {

    private final CookieProperties properties;

    @Override
    public void attachAccessTokenCookie(final HttpServletResponse response, final String value, final Duration maxAge) {
        addCookie(response, properties.name().refreshTokenName(), value, maxAge);
    }

    @Override
    public void attachRefreshTokenCookie(final HttpServletResponse response, final String value, final Duration maxAge) {
        addCookie(response, properties.name().refreshTokenName(), value, maxAge);
    }

    @Override
    public void clearAccessTokenCookie(final HttpServletResponse response) {
        clearCookie(response, properties.name().accessTokenName());
    }

    @Override
    public void clearRefreshTokenCookie(final HttpServletResponse response) {
        clearCookie(response, properties.name().refreshTokenName());
    }

    @Override
    public void addNoStoreHeaders(final HttpServletResponse response) {
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store, no-cache, must-revalidate, max-age=0");
        response.setHeader(HttpHeaders.PRAGMA, "no-cache");
        response.setHeader(HttpHeaders.EXPIRES, "0");
    }

    private void clearCookie(final HttpServletResponse response, final String name) {
        ResponseCookie.ResponseCookieBuilder builder =
                ResponseCookie.from(name, "")
                        .httpOnly(properties.cookieHttpOnly())
                        .secure(properties.cookieSecure())
                        .path("/")
                        .maxAge(Duration.ZERO)
                        .sameSite(properties.cookieSameSite());
        final String cookieDomain = properties.cookieDomain();
        if (cookieDomain != null && !cookieDomain.isBlank()) {
            builder.domain(cookieDomain);
        }
        response.addHeader(HttpHeaders.SET_COOKIE, builder.build().toString());
    }

    private void addCookie(final HttpServletResponse response, final String name, final String value, final Duration maxAge) {
        ResponseCookie.ResponseCookieBuilder builder = ResponseCookie.from(name, value)
                .httpOnly(properties.cookieHttpOnly())
                .secure(properties.cookieSecure())
                .path("/")
                .maxAge(maxAge)
                .sameSite(properties.cookieSameSite());
        final String cookieDomain = properties.cookieDomain();
        if (cookieDomain != null && !cookieDomain.isBlank()) {
            builder.domain(cookieDomain);
        }
        response.addHeader(HttpHeaders.SET_COOKIE, builder.build().toString());
    }
}
