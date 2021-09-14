package com.edso.resume.gw.config;

import com.edso.resume.gw.filter.AuthorizationFilter;
import com.edso.resume.gw.http.HeaderEnhanceFilter;
import com.edso.resume.gw.repo.SessionRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ServiceConfiguration {

    @Bean
    public AuthorizationFilter authorizationFilter(HeaderEnhanceFilter headerEnhanceFilter, SessionRepository cachedUserInfoRepo) {
        return new AuthorizationFilter(headerEnhanceFilter, cachedUserInfoRepo);
    }

    @Bean
    public HeaderEnhanceFilter headerEnhanceFilter() {
        return new HeaderEnhanceFilter();
    }

}
