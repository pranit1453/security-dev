package com.pranit.security.authentication.jwt.service;

import jakarta.servlet.http.HttpServletRequest;

@FunctionalInterface
public interface ResolveAccessToken {

    String getAccessTokenFromRequest(HttpServletRequest request);
}
