package com.developerscambodia.oauth2server.security.jackson;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public abstract class UserMixIn {

    @JsonCreator
    public UserMixIn(
            @JsonProperty("username") String username,
            @JsonProperty("password") String password
    ) {}

}
