package com.todobackend.todo.service;

import com.todobackend.todo.model.UserEntity;
import com.todobackend.todo.persistence.UserRepository;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Log4j2
@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    public UserEntity create (final UserEntity userEntity) {
        if(userEntity == null || userEntity.getUsername() == null) {
            throw new RuntimeException("Invalid arguments");
        }
        final String username = userEntity.getUsername();
        if(userRepository.existsByUsername(username)) { // 동일 사용자 계정 확인
            log.warn("Username already exists {}",username);
            throw new RuntimeException("Username already exists");
        }

        return userRepository.save(userEntity);
    }
    // getByCredentials 수정... 암호화된 패스워드를 확인하기 위해서...
    public UserEntity getByCredentials(final String username, final String password, PasswordEncoder encoder) {

        final UserEntity originalUser = userRepository.findByUsername(username);

        // matches 메서드를 이용해서 패스워드가 같은지 확인
        if(originalUser != null && encoder.matches(password, originalUser.getPassword())){
            return originalUser;
        }
        return null;
    }
}
