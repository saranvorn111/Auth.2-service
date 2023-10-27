package com.developerscambodia.oauth2resourceserver.controller;

import com.developerscambodia.oauth2resourceserver.service.GreetingService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequiredArgsConstructor
public class GreetingController {

    private final GreetingService greetingService;

    @GetMapping("/greeting")
    Map<String, String> greet() {
        return greetingService.greet();
    }

    @PreAuthorize("hasAuthority('delete')")
    @DeleteMapping("/greeting")
    Map<String, String> deleteGreeting() {
        return Map.of("message", "Delete successfully");
    }
}
