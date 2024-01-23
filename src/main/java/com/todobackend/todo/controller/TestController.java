package com.todobackend.todo.controller;

import lombok.extern.log4j.Log4j2;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Log4j2
@RestController
@RequestMapping("test") // 리소스
public class TestController {

    @GetMapping
    public String testController() {

        log.info("test");
        return "Hello World!";
    }
}