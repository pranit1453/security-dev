package com.pranit.security.authentication.oauth2.factory;

import com.pranit.security.authentication.constants.Provider;
import com.pranit.security.authentication.exception.ProviderNotFound;
import com.pranit.security.authentication.oauth2.stratergy.OAuth2Provider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Slf4j
@Component
public class OAuth2ProviderFactory {


    private final Map<Provider, OAuth2Provider> strategiesMap;

    public OAuth2ProviderFactory(List<OAuth2Provider> strategies) {
        this.strategiesMap = strategies.stream()
                .collect(Collectors.toMap
                        (OAuth2Provider::getProvider
                                , Function.identity()));
        log.info("OAuth2 provider factory initialized. supportedProviders: {}", strategiesMap.keySet());
    }

    public OAuth2Provider getStrategy(final Provider provider) {
        OAuth2Provider strategy = strategiesMap.get(provider);
        if (strategy == null) {
            log.warn("OAuth2 provider strategy not found. provider: {}", provider);
            throw new ProviderNotFound("No strategy found for provider");
        }
        log.debug("OAuth2 provider strategy resolved. provider: {}, strategy: {}",
                provider, strategy.getClass().getSimpleName());
        return strategy;
    }

}
