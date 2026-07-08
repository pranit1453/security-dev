package com.pranit.security.authentication.service;

import com.pranit.security.authentication.dto.SigninRequest;
import com.pranit.security.authentication.dto.SigninResponse;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

@FunctionalInterface
public interface LoginService {

    SigninResponse authenticateUser(@Valid SigninRequest request, HttpServletResponse response);
}
