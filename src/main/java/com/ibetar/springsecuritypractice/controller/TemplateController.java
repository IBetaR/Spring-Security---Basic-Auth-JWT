package com.ibetar.springsecuritypractice.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/")
public class TemplateController {

    @GetMapping(value = "login")
    public String getLoginView(){
        return "login";
    }

    @GetMapping(value = "courses")
    public String getCourses(){
        return "courses";
    }

}
