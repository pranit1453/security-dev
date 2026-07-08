package com.pranit.security.authentication.service;

import com.pranit.security.authentication.api.UserService;
import com.pranit.security.authentication.entity.UserDetail;
import com.pranit.security.authentication.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Override
    public Optional<UserDetail> findByUsername(final String username) {
        return userRepository.findByUsername(username);
    }
}
