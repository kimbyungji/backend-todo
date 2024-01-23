package com.todobackend.todo.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.GenericGenerator;

@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(uniqueConstraints = {@UniqueConstraint(columnNames = "username")})
public class UserEntity {

    @Id
    @GeneratedValue(generator = "system-uuid")
    @GenericGenerator(name="system-uuid", strategy = "uuid")
    private String id; // 유저에게 고유하게 부여되는 id값

    @Column(nullable = false)   // Not Null 설정
    private String username;    // 아이디로 사용할 유저네임. 이메일일 수도 있고 그냥 문자열일 수도 있어요
    private String password;    // 패스워드
    private String role;    // 사용자 롤. 역할 ex)admin, 일반 사용자
    private String authProvider;    // 이후에 OAuth에서 사용할 유저 정보 제공자...  : github, kakao, ...
}
