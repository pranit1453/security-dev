package com.pranit.security.authentication.jwt.service;

import com.pranit.security.shared.properties.CookieProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Arrays;

@Service
@RequiredArgsConstructor
public final class ResolveAccessTokenImpl implements ResolveAccessToken {

    private final CookieProperties properties;

    @Override
    public String getAccessTokenFromRequest(final HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return null;
        return Arrays.stream(cookies)
                .filter(cookie -> properties.name().accessTokenName().equals(cookie.getName()))
                .map(Cookie::getValue)
                .filter(value -> value != null && !value.isBlank())
                .findFirst()
                .orElse(null);
    }
}
