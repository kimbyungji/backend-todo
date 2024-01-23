package com.todobackend.todo.service;

import com.todobackend.todo.model.TodoEntity;
import com.todobackend.todo.persistence.TodoRepository;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@Log4j2
public class TodoService {

    @Autowired
    private TodoRepository repository;
    public String testService() {

        // TodoEntity 생성...
        TodoEntity entity = TodoEntity.builder().title("My first todo item").build();

        // TodoEntity 저장
        repository.save(entity);
        TodoEntity savedEntity = repository.findById(entity.getId()).get();

        return savedEntity.getTitle();
    }

    // create Todo
    public List<TodoEntity> create(final TodoEntity entity) {
        // 확인!!
        validate(entity);

        // 저장
        repository.save(entity);
        log.info("Entity Id : {} is saved ", entity.getId());

        return repository.findByUserId(entity.getUserId());
    }

    // retreive 메서드
    public List<TodoEntity> retrieve(final String userId) {

        return repository.findByUserId(userId);
    }

    // update 서비스 구현
    public List<TodoEntity> update(final TodoEntity entity) {
        // 1. 저장할 엔티티가 유효한지 확인...
        validate(entity);

        // 2. 넘겨받은 엔티티 id를 이용해서 TodoEntity를 가져온다. 왜? 존재하지 않는 엔티티를 업데이트 X
        final Optional<TodoEntity> original = repository.findById(entity.getId());

        original.ifPresent(todo-> {
            // 3. 변환할 TodoEntity가 존재하면 새 값으로 덮어 씌우기
            todo.setTitle(entity.getTitle());
            todo.setDone(entity.isDone());

            // 4. 데이터베이스에 새 값을 저장
            repository.save(todo);
        });

        return retrieve(entity.getUserId());
    }

    // delete 메서드
    public List<TodoEntity> delete(final TodoEntity entity) {
        // 1. 유효성 확인
        validate(entity);

        try {
            // 2. 엔티티 삭제
            repository.delete(entity);
        }catch (Exception e) {
            // 3. Exception 발생시 id와 exception을 로깅 처리...
            log.error("error deleting entity", entity.getId(), e);

            // 4. 컨트롤러로 Exception을 전달
            throw new RuntimeException("error deleting entity"+entity.getId());

        }

        // 5. 새 todo리스트를 리턴
        return retrieve(entity.getUserId());
    }

    // 리펙토링한 메서드
    private void validate(final TodoEntity entity) {

        if(entity == null) {    // 빈 객체
            log.warn("Entity cannot be null");
            throw new RuntimeException("Entity cannot be null");
        }

        if(entity.getUserId() == null){
            log.warn("Unknown User!");
            throw new RuntimeException("Unknown User!");
        }
    }

}
