package com.sinchin.practicespringsecurity.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/")
public class MainController {
    @GetMapping("/")
    public String viewDefaultPage() {
        return "home";
    }

    @GetMapping("/home")
    public String viewHomePage() {
        return "home";
    }

    @GetMapping("/admin/login")
    public String viewAdminLoginPage() {
        return "admin/admin_login";
    }

    @GetMapping("/admin/welcome")
    public String viewAdminWelcomePage() {
        return "admin/admin_welcome";
    }

    @GetMapping("/user/login")
    public String viewUserLoginPage() {
        return "user/user_login";
    }

    @GetMapping("/user/welcome")
    public String viewUserWelcomePage() {
        return "user/user_welcome";
    }
}
