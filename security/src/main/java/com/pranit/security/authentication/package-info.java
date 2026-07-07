@ApplicationModule(
        allowedDependencies = {"authorization::api", "shared", "authorization :: role"}
)

package com.pranit.security.authentication;

import org.springframework.modulith.ApplicationModule;