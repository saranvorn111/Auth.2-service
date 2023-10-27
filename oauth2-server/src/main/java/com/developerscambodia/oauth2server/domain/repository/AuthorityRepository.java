package com.developerscambodia.oauth2server.domain.repository;

import com.developerscambodia.oauth2server.domain.entity.Authority;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthorityRepository extends JpaRepository<Authority, Long> {
}
