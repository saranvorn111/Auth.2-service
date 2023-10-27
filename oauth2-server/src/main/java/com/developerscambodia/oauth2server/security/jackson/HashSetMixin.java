package com.developerscambodia.oauth2server.security.jackson;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

import java.util.Set;

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
public abstract class HashSetMixin {
    @JsonCreator
    HashSetMixin(Set<?> set) {
    }
}
