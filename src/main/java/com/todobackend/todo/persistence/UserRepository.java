package com.todobackend.todo.persistence;

import com.todobackend.todo.model.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<UserEntity, String> {

    // 사용자 정보를 불러오기(username으로)
    UserEntity findByUsername(String username);

    // 사용자 계정 여부를 확인(username으로)
    Boolean existsByUsername(String username);

    // 인증 처리를 위한 메서드
    UserEntity findByUsernameAndPassword(String username, String password);
}