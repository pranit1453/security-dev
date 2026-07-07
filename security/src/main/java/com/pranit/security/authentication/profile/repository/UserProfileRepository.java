package com.pranit.security.authentication.profile.repository;

import com.pranit.security.authentication.profile.entity.UserProfile;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface UserProfileRepository extends JpaRepository<UserProfile, UUID> {
}
