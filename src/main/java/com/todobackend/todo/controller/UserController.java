package com.todobackend.todo.controller;

import com.todobackend.todo.dto.ResponseDTO;
import com.todobackend.todo.dto.TodoDTO;
import com.todobackend.todo.dto.UserDTO;
import com.todobackend.todo.model.UserEntity;
import com.todobackend.todo.security.TokenProvider;
import com.todobackend.todo.service.UserService;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Log4j2
@RequestMapping("/auth")
public class UserController {

    @Autowired
    private UserService userService;

    //토큰 처리를 위한 Provider를 불러오기
    @Autowired
    private TokenProvider tokenProvider;

    private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @PostMapping("/signup")//여기서는 토큰을 발행할 이유가 없다.
    public ResponseEntity<?> registerUser(@RequestBody UserDTO userDTO){
        try{
            if(userDTO == null || userDTO.getPassword() == null) {
                throw new RuntimeException("Invalid Password value"); //데이터와 비번이 없으면 예외처리
            }
            //요청을 이용해서 저장할 유저 만들기 - UserEntity 객체 만들기
            UserEntity user = UserEntity.builder()
                    .username(userDTO.getUsername())
                    .password(passwordEncoder.encode(userDTO.getPassword()))
                    .build();

            log.info("생성한 사용자의 패스워드 : "+user.getPassword());

            //서비스를 이용해서 repository에 유저 저장
            UserEntity registeredUser = userService.create(user); //퍼시스트 컨텍스트에 등록. save 되니까
            //----------- 사용자 생성 과정 끝, 응답 과정 시작 -----------

            //반환 값
            UserDTO responseUserDTO = UserDTO.builder()
                    .id(registeredUser.getId())
                    .username(registeredUser.getUsername())
                    .build();

            return ResponseEntity.ok().body(responseUserDTO);

        }catch(Exception e) {
            //유저 정보는 항상 하나의 결과이기 때문에 리스트로 만들어 사용한 responseDTO를 사용하지 않은 상태로 구현
            //하지만 예외가 발생하면 그 예외에 대한 처리를 위해서 responseDTO를 사용한다. - 에러에 데이터를 실어 전달하기 위해 ResponseDTO 사용
            ResponseDTO responseDTO = ResponseDTO.builder().error(e.getMessage()).build();
            return ResponseEntity.badRequest().body(responseDTO);
        }
    }

    //사용자 인증
    @PostMapping("/signin")//여기서는 토큰 발행이 필요하다.
    public ResponseEntity<?> authenticate(@RequestBody UserDTO userDTO) {
        UserEntity user = userService.getByCredentials(//getByCredentials = 정보를 받아서 사용자가 있는지 없는지 판단
                //getByCredentials에 인증처리에 필요한 정보 넘기기
                userDTO.getUsername(),
                userDTO.getPassword(),
                passwordEncoder
        );

        if(user != null) {//로그인 성공
            //로그인을 성공했다면 토큰을 발행해 준다.
            final String token = tokenProvider.create(user);
            final UserDTO responseUserDTO = UserDTO.builder()
                    .username(user.getUsername())
                    .id(user.getId())
                    .token(token)//UserDTO에 token 데이터를 넘겨준다.
                    //password는 넘길 수 없다.
                    .build();
            return ResponseEntity.ok().body(responseUserDTO);
        }else {//로그인 실패
            ResponseDTO responseDTO = ResponseDTO.builder()
                    .error("Login failed").build();
            return ResponseEntity.badRequest().body(responseDTO);
        }
    }
}