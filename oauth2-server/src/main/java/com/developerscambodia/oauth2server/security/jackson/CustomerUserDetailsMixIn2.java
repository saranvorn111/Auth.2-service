package com.developerscambodia.oauth2server.security.jackson;

import com.developerscambodia.oauth2server.domain.entity.User;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public abstract class CustomerUserDetailsMixIn2 {
    @JsonCreator
    public CustomerUserDetailsMixIn2(
            @JsonProperty("user") User user
    ) {}
}
