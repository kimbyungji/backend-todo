package com.todobackend.todo.security;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.todobackend.todo.model.UserEntity;
import com.todobackend.todo.persistence.UserRepository;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Log4j2
@Service
public class OAuthUserServiceImpl extends DefaultOAuth2UserService {

    @Autowired
    private UserRepository userRepository;

    public OAuthUserServiceImpl() {
        super();
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // DefaultOAuth2UserService의 기존 loadUser를 호출...
        // 이 메서드가 user-info-uri를 이용해서 사용자 정보를 가져오는 부분이 됩니다.
        final  OAuth2User oAuth2User = super.loadUser(userRequest);

        try {
          // 디버깅을 돕기 위해서 사용자 정보가 어떻게 되는지 로깅 처리... 테스트 시에만 사용!
            log.info("OAuth2User attributes {}", new ObjectMapper()
                    .writeValueAsString(oAuth2User.getAttributes()));
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }

        // login 필드를 가져온다.
        final String username = (String)oAuth2User.getAttributes().get("login");
        final String authProvider = userRequest.getClientRegistration().getClientName();

        UserEntity userEntity = null;

        // 유저가 존재하지 않으면 새로 생성한다...
        if(!userRepository.existsByUsername(username)){
            userEntity = UserEntity.builder()
                    .username(username)
                    .authProvider(authProvider)
                    .build();
            userEntity = userRepository.save(userEntity);
        } else{
            userEntity = userRepository.findByUsername(username);
        }
        log.info("Successfully pulled user info username {} authProvider {}",
                username,
                authProvider);

        return new ApplicationOAuth2Usser(userEntity.getId(), oAuth2User.getAttributes());
    }
}
