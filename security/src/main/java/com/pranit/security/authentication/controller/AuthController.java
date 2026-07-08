package com.pranit.security.authentication.controller;

import com.pranit.security.authentication.dto.SigninRequest;
import com.pranit.security.authentication.dto.SigninResponse;
import com.pranit.security.authentication.dto.TokenResponse;
import com.pranit.security.authentication.service.LoginService;
import com.pranit.security.authentication.service.LogoutService;
import com.pranit.security.authentication.service.TokenService;
import com.pranit.security.shared.exception.Unauthorized;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Validated
public class AuthController {

    private final LoginService loginService;
    private final TokenService tokenService;
    private final LogoutService logoutService;

    /**
     * api authenticateUser(username,password) --> call authentication manager --> call authentication provider --> call userDetailService --> call database to fetch data
     * once data is validated then security context holder confirms that request is authenticated
     * after that Access token is generated for client and send back to client
     * in HttpOnlyCookie
     */
    @PostMapping("/login")
    public ResponseEntity<SigninResponse> login(@RequestBody @Valid SigninRequest request, final HttpServletResponse response) {
        return ResponseEntity.ok(loginService.authenticateUser(request, response));
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refreshToken(final HttpServletRequest request, final HttpServletResponse response) {
        String refreshToken = tokenService.readRefreshTokenFromRequest(request)
                .orElseThrow(() -> {
                    log.warn("No refresh token found");
                    return new Unauthorized("No refresh token found");
                });

        return ResponseEntity.status(HttpStatus.OK)
                .body(tokenService.generateNewRefreshToken(refreshToken, response));
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(final HttpServletRequest request, final HttpServletResponse response) {
        logoutService.readRefreshTokenFromRequest(request)
                .ifPresent(logoutService::revokedRefreshToken);
        logoutService.readAccessTokenFromRequest(request)
                .ifPresent(logoutService::revokedAccessToken);
        logoutService.clearResponse(response);
        log.info("User logged out successfully");
        return ResponseEntity.ok("Logout successful");
    }
}
