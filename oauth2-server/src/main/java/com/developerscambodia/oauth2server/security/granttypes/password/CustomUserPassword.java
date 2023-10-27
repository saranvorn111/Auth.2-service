package com.developerscambodia.oauth2server.security.granttypes.password;

import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public record CustomUserPassword(String username, Collection<? extends GrantedAuthority> authorities) {
}
