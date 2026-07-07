@ApplicationModule(
        allowedDependencies = {"authorization::api", "shared", "authorization :: role", "otp :: api", "otp"}
)

package com.pranit.security.authentication;

import org.springframework.modulith.ApplicationModule;