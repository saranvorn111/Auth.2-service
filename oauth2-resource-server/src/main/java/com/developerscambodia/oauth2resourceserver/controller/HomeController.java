package com.developerscambodia.oauth2resourceserver.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;

@RestController
@Slf4j
public class HomeController {

    @PreAuthorize("isAnonymous()")
    @GetMapping("/public")
    public String getPublic() {
        return "public end-point";
    }

    @PreAuthorize("isAuthenticated()")
    @GetMapping
    public String home(Authentication authentication) {
        LocalDateTime time = LocalDateTime.now();
        log.info("AUTH: {}", authentication.getAuthorities());
        return String.format("Welcome home!\n%s\n%s\n%s",
                authentication.getName(),
                authentication.getAuthorities(),
                time);
    }

}
