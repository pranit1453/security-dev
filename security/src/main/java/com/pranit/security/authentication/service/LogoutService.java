package com.pranit.security.authentication.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.Optional;

public interface LogoutService {
    Optional<String> readRefreshTokenFromRequest(HttpServletRequest request);

    void revokedRefreshToken(String token);

    Optional<String> readAccessTokenFromRequest(HttpServletRequest request);

    void revokedAccessToken(String token);

    void clearResponse(HttpServletResponse response);
}
