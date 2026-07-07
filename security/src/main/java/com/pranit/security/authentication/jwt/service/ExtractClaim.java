package com.pranit.security.authentication.jwt.service;

import io.jsonwebtoken.Claims;

import java.util.UUID;

public interface ExtractClaim {

    String getUsernameFromAccessToken(Claims claims);

    String getUsernameFromRefreshToken(Claims claims);

    UUID getUserIdFromAccessToken(Claims claims);

    String getJtiFromRefreshToken(Claims claims);

    Claims validateAndParseToken(String token);

    boolean isRefreshToken(Claims claims);

    boolean isAccessToken(Claims claims);

    String getSessionIdFromAccessToken(Claims claims);
}
