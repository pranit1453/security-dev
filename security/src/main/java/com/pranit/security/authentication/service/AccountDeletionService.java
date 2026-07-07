package com.pranit.security.authentication.service;

import java.util.UUID;

@FunctionalInterface
public interface AccountDeletionService {

    void deleteUserAccountPermanently(UUID userId);

}
