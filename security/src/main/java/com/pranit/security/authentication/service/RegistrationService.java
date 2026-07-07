package com.pranit.security.authentication.service;

import com.pranit.security.authentication.dto.RegistrationRequest;
import com.pranit.security.authentication.dto.SignupResponse;
import jakarta.validation.Valid;

public interface RegistrationService {

    SignupResponse createNewUserAccount(@Valid RegistrationRequest request);

    SignupResponse createNewAdminAccount(@Valid RegistrationRequest request);
}
