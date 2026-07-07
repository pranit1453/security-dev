package com.pranit.security.authentication.jwt.endpoints;

import org.springframework.stereotype.Service;

@Service
public class PublicEndpointProviderImpl implements PublicEndpointProvider {

    private static final String[] PUBLIC_ENDPOINTS = {

    };

    @Override
    public String[] publicEndpoints() {
        return PUBLIC_ENDPOINTS;
    }
}
