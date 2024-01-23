package com.todobackend.todo.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;

// 상수값 불러오기
import static com.todobackend.todo.security.RedirectUrlCookieFiilter.REDIRECT_URI_PARAM;

@Log4j2
@Component
@AllArgsConstructor
public class OAuthSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private static final String LOCAL_REDIRECT_URL = "http://localhost:3000";

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        TokenProvider tokenProvider = new TokenProvider();
        String token = tokenProvider.create(authentication);

        Optional<Cookie> oCookie = Arrays.stream(request.getCookies()).filter(
                cookie -> cookie.getName().equals(REDIRECT_URI_PARAM)).findFirst();
        Optional<String> redirectUri = oCookie.map(Cookie::getValue);
        
//        response.getWriter().write(token);
        log.info("token {}", token);
        response.sendRedirect(redirectUri.orElseGet(() -> LOCAL_REDIRECT_URL)+
                "/sociallogin?token="+token);
    }
}