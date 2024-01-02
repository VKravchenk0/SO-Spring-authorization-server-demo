package com.github.vkravchenk0.demo.controller;

import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Tag(name = "Controller protected by the session cookie obtained by the /login endpoint")
public class TestSessionSecurityController {

    @GetMapping("/test/protected")
    public String protectedEndpoint() {
        return "PROTECTED STRING";
    }

    @GetMapping("/test/unprotected")
    public String unprotectedEndpoint() {
        return "UNPROTECTED STRING";
    }

    @GetMapping("/test/currentUser")
    @ResponseBody
    public String currentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication instanceof AnonymousAuthenticationToken)) {
            String currentUserName = authentication.getName();
            return authentication.getClass() + ": " + currentUserName;
        }
        return "anonymous";
    }

}