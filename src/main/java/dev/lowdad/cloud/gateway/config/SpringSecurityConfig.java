package dev.lowdad.cloud.gateway.config;

import dev.lowdad.cloud.common.enums.TokenStoreType;
import dev.lowdad.cloud.common.model.vo.UserInfoVO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cglib.beans.BeanMap;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;
import org.springframework.security.oauth2.server.resource.web.server.ServerBearerTokenAuthenticationConverter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.reactive.CorsUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.Map;

/**
 * <p>
 *
 * </P>
 *
 * @author Chongyu
 * @since 2020/9/24
 */
@Configuration
public class SpringSecurityConfig {

    private static final String MAX_AGE = "18000L";
    private final TokenStoreType tokenStoreType = TokenStoreType.JWT;
    private final RedisConnectionFactory redisConnectionFactory;
    private final AccessManager accessManager;
    private final JwtSignConfiguration jwtSignConfiguration;

    @Autowired
    public SpringSecurityConfig(RedisConnectionFactory redisConnectionFactory, AccessManager accessManager, JwtSignConfiguration jwtSignConfiguration) {
        this.redisConnectionFactory = redisConnectionFactory;
        this.accessManager = accessManager;
        this.jwtSignConfiguration = jwtSignConfiguration;
    }

    /**
     * jwt 序列化,signKey 可配置
     *
     * @return JwtAccessTokenConverter
     */
    @Bean
    @RefreshScope
    public JwtAccessTokenConverter jwtTokenEnhancer() {
        JwtAccessTokenConverter jwtTokenEnhancer = new JwtAccessTokenConverter();
        jwtTokenEnhancer.setSigningKey(jwtSignConfiguration.getSignKey());
        ((DefaultAccessTokenConverter) jwtTokenEnhancer.getAccessTokenConverter()).setUserTokenConverter(new DefaultUserAuthenticationConverter() {
            @Override
            public Authentication extractAuthentication(Map<String, ?> map) {
                UserInfoVO userInfoVO = new UserInfoVO();
                BeanMap.create(userInfoVO).putAll(map);
                Object authorities = map.get("authorities");
                if (authorities instanceof String) {
                    userInfoVO.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList((String) authorities));
                } else if (authorities instanceof Collection) {
                    userInfoVO.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList(StringUtils.collectionToCommaDelimitedString((Collection) authorities)));
                }
                return new PreAuthenticatedAuthenticationToken(userInfoVO, null, userInfoVO.getAuthorities());
            }
        });
        return jwtTokenEnhancer;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 定义token存储方式
     *
     * @return TokenStore
     */
    @Bean
    public TokenStore tokenStore() {
        switch (tokenStoreType) {
            case REDIS:
                return new RedisTokenStore(redisConnectionFactory);
            case JWT:
                return new JwtTokenStore(jwtTokenEnhancer());
        }
        return new InMemoryTokenStore();
    }


    /**
     * 跨域配置
     */
    public WebFilter corsFilter() {
        return (ServerWebExchange ctx, WebFilterChain chain) -> {
            ServerHttpRequest request = ctx.getRequest();
            if (CorsUtils.isCorsRequest(request)) {
                HttpHeaders requestHeaders = request.getHeaders();
                ServerHttpResponse response = ctx.getResponse();
                HttpMethod requestMethod = requestHeaders.getAccessControlRequestMethod();
                HttpHeaders headers = response.getHeaders();
                headers.add(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, requestHeaders.getOrigin());
                headers.addAll(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS, requestHeaders.getAccessControlRequestHeaders());
                if (requestMethod != null) {
                    headers.add(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS, requestMethod.name());
                }
                headers.add(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
                headers.add(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, "*");
                headers.add(HttpHeaders.ACCESS_CONTROL_MAX_AGE, MAX_AGE);
                if (request.getMethod() == HttpMethod.OPTIONS) {
                    response.setStatusCode(HttpStatus.OK);
                    return Mono.empty();
                }
            }
            return chain.filter(ctx);
        };
    }

    @Bean
    public SecurityWebFilterChain webFluxSecurityFilterChain(ServerHttpSecurity httpSecurity) throws Exception{
        //token管理器
        org.springframework.security.authentication.ReactiveAuthenticationManager tokenAuthenticationManager = new CustomerReactiveAuthenticationManager(tokenStore());
        //认证过滤器
        AuthenticationWebFilter authenticationWebFilter = new AuthenticationWebFilter(tokenAuthenticationManager);
        authenticationWebFilter.setServerAuthenticationConverter(new ServerBearerTokenAuthenticationConverter());

        httpSecurity
                .httpBasic().disable()
                .csrf().disable()
                .authorizeExchange()
                .pathMatchers(HttpMethod.OPTIONS).permitAll()
                .anyExchange().access(accessManager)
                .and()
                // 跨域过滤器
                .addFilterAt(corsFilter(), SecurityWebFiltersOrder.CORS)
                //oauth2认证过滤器
                .addFilterAt(authenticationWebFilter, SecurityWebFiltersOrder.AUTHENTICATION);
        return httpSecurity.build();
    }
}
