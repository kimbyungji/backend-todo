package com.todobackend.todo.config;

import com.todobackend.todo.security.JwtAuthenticationFilter;
import com.todobackend.todo.security.OAuthSuccessHandler;
import com.todobackend.todo.security.OAuthUserServiceImpl;
import com.todobackend.todo.security.RedirectUrlCookieFiilter;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.Arrays;

@EnableWebSecurity
@Log4j2
@Configuration
public class WebSecurityConfig {
    // WebSecurity
    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Autowired
    private OAuthUserServiceImpl oAuthUserService;  // security에 생성한

    @Autowired
    private OAuthSuccessHandler oAuthSuccessHandler;

    @Autowired
    private RedirectUrlCookieFiilter redirectUrlCookieFiilter;

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(
                Arrays.asList("http://localhost:3000","http://app.qudwl.p-e.kr","https://app.qudwl.p-e.kr"));
        configuration.setAllowedMethods(
                Arrays.asList("GET","POST","PUT","PATCH","DELETE","OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**",configuration);
        return source;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.cors(cors -> cors.configurationSource(corsConfigurationSource()));
        http.addFilterAfter(jwtAuthenticationFilter, CorsFilter.class);
        http.csrf(csrf->csrf.disable());
        http.httpBasic(httpBasic -> httpBasic.disable());
        http.sessionManagement(sessionManagement ->
                sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.authorizeHttpRequests(httpAuth -> {
                    httpAuth.requestMatchers("/", "/auth/**","/oauth2/**").permitAll();
                    httpAuth.anyRequest().authenticated();
                });
        http.oauth2Login(oauth -> {
            oauth.redirectionEndpoint(redirect ->
                    redirect.baseUri("/oauth2/callback/*"));
            oauth.authorizationEndpoint(authEnd ->
                    authEnd.baseUri("/auth/authorize"));
            oauth.userInfoEndpoint(userInfo ->
                    userInfo.userService(oAuthUserService));
            oauth.successHandler(oAuthSuccessHandler);  //Sucess Handler 등록
        }); // 수정
        http.exceptionHandling(except
                -> except.authenticationEntryPoint(new Http403ForbiddenEntryPoint()));
        http.addFilterBefore(
                redirectUrlCookieFiilter,
                OAuth2AuthorizationRequestRedirectFilter.class  // 리다이렉트되기 전에 필터 실행
        );
        return http.build();
    }

}
