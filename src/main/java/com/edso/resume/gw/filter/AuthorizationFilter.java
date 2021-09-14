package com.edso.resume.gw.filter;

import com.edso.resume.gw.http.HeaderEnhanceFilter;
import com.edso.resume.gw.jwt.AuthResponse;
import com.edso.resume.gw.repo.SessionRepository;
import com.edso.resume.lib.common.ErrorCodeDefs;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Stream;

public class AuthorizationFilter implements GlobalFilter, Ordered {

    private final HeaderEnhanceFilter headerEnhanceFilter;

    private final SessionRepository cachedUserInfoRepo;

    public AuthorizationFilter(HeaderEnhanceFilter headerEnhanceFilter, SessionRepository cachedUserInfoRepo) {
        this.headerEnhanceFilter = headerEnhanceFilter;
        this.cachedUserInfoRepo = cachedUserInfoRepo;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        AuthResponse response = headerEnhanceFilter.doFilter(request, cachedUserInfoRepo);
        String requestUri = request.getURI().getPath();
        if (isAuthenticatedUrl(requestUri) && !isImageUrl(requestUri)) {
            if (response.getCode() != ErrorCodeDefs.ERROR_CODE_OK) {
                exchange.getResponse().setStatusCode(HttpStatus.OK);
                byte[] bytes = response.toJson().getBytes(StandardCharsets.UTF_8);
                DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
                return exchange.getResponse().writeWith(Flux.just(buffer));
            }
        }
        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return -200;
    }

    static Set<String> auths = new HashSet<>();

    static {
        auths.add("/auth/login");
        auths.add("/auth/register");
        auths.add("/auth/forgot-password");
        auths.add("/swagger");
    }

    private boolean isAuthenticatedUrl(String url) {
        for (String a : auths) {
            if (url.contains(a)) {
                return false;
            }
        }
        return true;
    }

    private boolean isImageUrl(String url) {
        return Stream.of(".jpg", ".JPG", ".jpeg", ".JPEG", ".png", ".PNG").anyMatch(url::endsWith);
    }

}
