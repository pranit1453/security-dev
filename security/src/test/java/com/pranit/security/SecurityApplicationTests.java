package com.pranit.security;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.modulith.ApplicationModule;
import org.springframework.modulith.core.ApplicationModules;

@SpringBootTest
class SecurityApplicationTests {

	@Test
	void contextLoads() {
        var modules = ApplicationModules.of(SecurityApplication.class);
        modules.verify();
	}

}
