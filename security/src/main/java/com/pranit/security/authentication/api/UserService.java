package com.pranit.security.authentication.api;

import com.pranit.security.authentication.entity.UserDetail;

import java.util.Optional;

public interface UserService {
    Optional<UserDetail> findByUsername(String username);
}
