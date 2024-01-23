package com.todobackend.todo.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    // for healthCheck
    @RequestMapping("/")
    public String home() {
        return "The Server is up and running....";
    }

}
