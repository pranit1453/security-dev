package com.pranit.security.authentication.jwt.service;

import com.pranit.security.authentication.entity.UserDetail;

public interface GenerateToken {
    String generateAccessToken(UserDetail userDetail, String sessionId);

    String generateRefreshToken(UserDetail userDetail, String jti, String sessionId);

}
