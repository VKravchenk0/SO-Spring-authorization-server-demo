package com.github.vkravchenk0.demo.controller;

import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Tag(name = "Test controller protected by the OAuth2 authorization")
@SecurityRequirement(name = "Bearer Authentication")
public class TestOauth2SecurityController {

    @GetMapping("/api/test/protected")
    public String apiProtectedEndpoint() {
        return "JWT PROTECTED STRING";
    }

    @GetMapping("/api/test/unprotected")
    public String apiUnprotectedEndpoint() {
        return "JWT UNPROTECTED STRING";
    }

    @GetMapping("/api/test/currentUser")
    @ResponseBody
    public String apiCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication instanceof AnonymousAuthenticationToken)) {
            String currentUserName = authentication.getName();
            return authentication.getClass() + ": " + currentUserName;
        }
        return "anonymous";
    }

}