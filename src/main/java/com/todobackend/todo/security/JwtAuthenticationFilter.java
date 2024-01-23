package com.todobackend.todo.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Log4j2
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private TokenProvider tokenProvider;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        try {
            //요청에서 토큰 가져오기
            String token = parseBearerToken(request);
            log.info("Filter is running.... ");
            //토큰 검사하기. JWT이므로 인가 서버에 요청하지 않고도 검증 가능...
            if(token != null && !token.equalsIgnoreCase("null")){
                //userId 가져오기. 위조된 경우에는 예외 처리...
                String userId = tokenProvider.validateAndGetUserId(token);
                log.info("Authenticated user ID : "+ userId);
                // 인증완료!!! securityContextHolder에 등록해야 인증된 사용자로 생각함.
                AbstractAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userId, //인증된 사용자의 정보. 문자열이 아니엉도 아무거나 넣을 수 있음.
                        // 보통은 UserDetails라는 오브젝트를 넣습니다. 안만들었음....
                        null,   // 비밀번호
                        AuthorityUtils.NO_AUTHORITIES   // 권한
                );
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
                securityContext.setAuthentication(authentication);
                SecurityContextHolder.setContext(securityContext);
            }
        }catch (Exception ex){
            log.error("Could not set user authentication in security context", ex);
        }
        filterChain.doFilter(request,response);
    }

    private String parseBearerToken(HttpServletRequest request){
        // Http 요청의 헤더를 파싱해서 Bearer 토큰을 리턴
        String bearerToken = request.getHeader("Authorization");

        if(StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")){
            return bearerToken.substring(7);
        }
        return null;
    }
}