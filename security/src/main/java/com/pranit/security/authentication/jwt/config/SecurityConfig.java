package com.pranit.security.authentication.jwt.config;

import com.pranit.security.authentication.jwt.endpoints.PublicEndpointProvider;
import com.pranit.security.authentication.jwt.entrypoint.AuthenticationTokenEntryPoint;
import com.pranit.security.authentication.jwt.filter.AuthenticationTokenFilter;
import com.pranit.security.authentication.jwt.service.OAuth2AuthenticationFailureHandler;
import com.pranit.security.authentication.jwt.service.OAuth2AuthenticationSuccessHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableMethodSecurity
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(final HttpSecurity http,
                                    final AuthenticationTokenEntryPoint entryPoint,
                                    final PublicEndpointProvider publicEndpointProvider,
                                    final OAuth2AuthenticationSuccessHandler successHandler,
                                    final OAuth2AuthenticationFailureHandler failureHandler,
                                    final AuthenticationTokenFilter filter) {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(request -> request
                        .requestMatchers(publicEndpointProvider.publicEndpoints()).permitAll()
                        .anyRequest().authenticated())
                .oauth2Login(oauth2 -> oauth2
                        .successHandler(successHandler)
                        .failureHandler(failureHandler))
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(entryPoint))
                .addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    AuthenticationManager authenticationManager(final AuthenticationConfiguration builder) {
        return builder.getAuthenticationManager();
    }

}
