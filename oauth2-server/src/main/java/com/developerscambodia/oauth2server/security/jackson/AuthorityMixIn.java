package com.developerscambodia.oauth2server.security.jackson;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public abstract class AuthorityMixIn {

    @JsonCreator
    public AuthorityMixIn(
            @JsonProperty("id") Integer id,
            @JsonProperty("name") String name
    ) {}

}
