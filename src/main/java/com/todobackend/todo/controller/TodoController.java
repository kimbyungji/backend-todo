package com.todobackend.todo.controller;

import com.todobackend.todo.dto.ResponseDTO;
import com.todobackend.todo.dto.TodoDTO;
import com.todobackend.todo.model.TodoEntity;
import com.todobackend.todo.service.TodoService;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Log4j2
@RestController
@RequestMapping("todo")
public class TodoController {

    @Autowired
    private TodoService todoService;

    @GetMapping("/test")
    public ResponseEntity<?> testTodo() {
        String str = todoService.testService(); // 테스트 서비스 이용
        List<String> list = new ArrayList<>();
        list.add(str);
        ResponseDTO<String> response = ResponseDTO.<String>builder()
                .data(list).build();

        return ResponseEntity.ok().body(response);
    }

    // create 작업 (RESTful, GET, POST, PUT, PATCH, DELETE ...)
    @PostMapping
    public ResponseEntity<?> createTodo(@AuthenticationPrincipal String userId,
                                        @RequestBody TodoDTO dto) {
        log.info("AuthenticationPrincipal : "+ userId);
        try {
//            String temporaryUserId = "temporary-user";  // 임시유저로 나중에 삭제...

            // 1. DTO -> TodoEntity로 변환
            TodoEntity entity = TodoDTO.todoEntity(dto);    // entity로 변환

            // 2. id를 null로 초기화... 왜? 생성시 id가 존재하면 안됨...
            entity.setId(null);

            // 3. 임시 유저를 userId에 설정...
            entity.setUserId(userId);

            // 4. 서비스를 이용해서 TodoEntity 생성
            List<TodoEntity> entities = todoService.create(entity);

            // --------------- 생성 과정 끝, 응답 과정 시작....
            // 5. 자바 스트림을 이용해서 리턴된 엔티티 리스트를 TodoDTO리스트로 변환
                List<TodoDTO> dtos = entities.stream().map(TodoDTO::new).collect(Collectors.toList());

            // 6. 변환된 TodoDTO리스트를 이용해서 ResponseDTO를 초기화...
            ResponseDTO<TodoDTO> response = ResponseDTO.<TodoDTO>builder().data(dtos).build();

            // 7. ResponseDTO를 리턴
            return ResponseEntity.ok().body(response);
        }catch (Exception e) {
            // 8. 예외가 발생하는 경우 data에 dto 대신 error에 메세지를 담아서 전달
            String error  = e.getMessage();
            ResponseDTO<TodoDTO> response = ResponseDTO.<TodoDTO>builder().error(error).build();
            return ResponseEntity.badRequest().body(response);
        }
    }

    @GetMapping
    public  ResponseEntity<?> retrieveTodoList(@AuthenticationPrincipal String userId) {
//        String temporaryUserId = "temporary-user";  // 임시 유저

        // 1. 서비스 메서드를 호출(retrieve 메서드를 호출)
        List<TodoEntity> entities = todoService.retrieve(userId);
        
        // 2. 자바 스트림을 이용해서 리턴된 엔티티 리스트를 TodoDTO리스트로 변환
        List<TodoDTO> dtos = entities.stream().map(TodoDTO::new).collect(Collectors.toList());

        // 3. 변환된 TodoDTO 리스트를 이용하여 ResponseDTO로 초기화
        ResponseDTO<TodoDTO> response = ResponseDTO.<TodoDTO>builder().data(dtos).build();

        // 4. ResponseDTO를 리턴
        return ResponseEntity.ok().body(response);
    }

    @PutMapping
    public ResponseEntity<?> updateTodo(@AuthenticationPrincipal String userId, @RequestBody TodoDTO dto) {
//        String temporaryUserId = "temporary-user";  // 임시 유저

        // 1. dto를 entity로 변환
        TodoEntity entity = TodoDTO.todoEntity(dto);
        
        // 2. id를 temporaryUserId로 초기화
        entity.setUserId(userId);

        // 3. 서비스를 이용해서 entity를 업데이트 처리
        List<TodoEntity> entities = todoService.update(entity);
        // -----------------------------------------------------
        // 4. 자바 스트림을 이용한 리턴된 엔티티를 TodoDTO리스트로 변환
        List<TodoDTO> dtos = entities.stream().map(TodoDTO::new).collect(Collectors.toList());

        // 5. ResponseDTO를 초기화
        ResponseDTO<TodoDTO> response = ResponseDTO.<TodoDTO>builder().data(dtos).build();

        // 6. ResponseDTO를 리턴
        return ResponseEntity.ok().body(response);
    }

    @DeleteMapping
    public ResponseEntity<?> deleteTodo(@AuthenticationPrincipal String userId, @RequestBody TodoDTO dto) {
        try {
//            String temporaryUserId = "temporary-user";  // 임시 유저

            // 1. TodoEntity 변환
            TodoEntity entity = TodoDTO.todoEntity(dto);

            // 2. setUserId설정
            entity.setUserId(userId);

            // 3. 서비스를 이용해서 entity 삭제 처리
            List<TodoEntity> entities = todoService.delete(entity);

            //------------------------------------------------------
            // 4. 자바 스트림을 이용해서 리턴값을 변환 (TodoDTO리스트로)
            List<TodoDTO> dtos = entities.stream().map(TodoDTO::new).collect(Collectors.toList());

            // 5. 변환된 TodoDTO 리스트를 ResponseDTO로 초기화
            ResponseDTO<TodoDTO> response = ResponseDTO.<TodoDTO>builder().data(dtos).build();

            // 6. ResponseDTO를 전달
            return ResponseEntity.ok().body(response);
        }catch (Exception e) {
            // 7. 예외 발생시...
            String error = e.getMessage();
            ResponseDTO<TodoDTO> response = ResponseDTO.<TodoDTO>builder().error(error).build();

            return ResponseEntity.badRequest().body(response);
        }
    }
}
