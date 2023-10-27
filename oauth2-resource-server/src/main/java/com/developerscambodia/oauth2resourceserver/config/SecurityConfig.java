package com.developerscambodia.oauth2resourceserver.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    // TODO: configuration for OAuth 2.0 Authorization with JWT
    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;

    // TODO: configuration for OAuth 2.0 Authorization Server with Opaque Token
    /*@Value("${spring.security.oauth2.resourceserver.opaquetoken.introspection-uri}")
    private String opaqueIssuerUri;
    @Value("${spring.security.oauth2.resourceserver.opaquetoken.client-id}")
    private String opaqueClientId;
    @Value("${spring.security.oauth2.resourceserver.opaquetoken.client-secret}")
    private String opaqueClientSecret;*/

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity security) throws Exception {

        return security

                /*.authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated())*/

                // TODO: configuration for OAuth 2.0 Authorization Server with JWT
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwtConfigurer -> jwtConfigurer.decoder(JwtDecoders.fromIssuerLocation(issuerUri))))

                // TODO: configuration for OAuth 2.0 Authorization Server with Opaque Token
                /*.oauth2ResourceServer(oauth2 -> oauth2
                        .opaqueToken(opaqueTokenConfigurer -> opaqueTokenConfigurer
                                .introspectionUri(opaqueIssuerUri)
                                .introspectionClientCredentials(opaqueClientId, opaqueClientSecret))
                        )*/

                .build();
    }

    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter() {

        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName("authorities");
        jwtGrantedAuthoritiesConverter.setAuthorityPrefix("");

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);

        return jwtAuthenticationConverter;
    }

}
