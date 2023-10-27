package com.developerscambodia.oauth2server.config;

import com.developerscambodia.oauth2server.security.JpaRegisteredClientRepository;
import com.developerscambodia.oauth2server.security.granttypes.password.CustomPasswordAuthenticationConverter;
import com.developerscambodia.oauth2server.security.granttypes.password.CustomPasswordAuthenticationProvider;
import com.developerscambodia.oauth2server.security.granttypes.password.CustomUserPassword;
import com.developerscambodia.oauth2server.security.JpaOAuth2AuthorizationService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.token.DefaultToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2TokenEndpointConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Collectors;

@Configuration
//@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    //private final JpaOAuth2AuthorizationService jpaOAuth2AuthorizationService;
    //private final JpaRegisteredClientRepository jpaRegisteredClientRepository;
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    /*private Consumer<List<AuthenticationProvider>> getProviders() {
        return a -> a.forEach(System.out::println);
    }

    private Consumer<List<AuthenticationConverter>> getConverters() {
        return a -> a.forEach(System.out::println);
    }*/

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);
        return daoAuthenticationProvider;
    }

    @Bean
    @Order(1)
    public SecurityFilterChain webSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);

        httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class)

                // TODO: Custom OAuth 2.0 consent page
                /*.authorizationEndpoint(endpoint -> endpoint
                        .consentPage("/oauth2/consent"))*/

                // TODO: Custom password grant_type
                /*.tokenEndpoint(token -> token
                        .accessTokenRequestConverter(new CustomPasswordAuthenticationConverter())
                        .authenticationProvider(new CustomPasswordAuthenticationProvider(jpaOAuth2AuthorizationService, tokenGenerator(), userDetailsService, passwordEncoder))
                        .accessTokenRequestConverters(getConverters())
                        .authenticationProviders(getProviders()))*/

                // TODO: Using default OpenID Connect
                .oidc(Customizer.withDefaults());




        // TODO: Exception happens will redirect to `/login`
        httpSecurity.exceptionHandling(
                c -> c.defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"),
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
        );

        // TODO: Accept access tokens for user info and/or client registration
        // httpSecurity.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));

        return httpSecurity.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain appSecurity(HttpSecurity httpSecurity) throws Exception {

        httpSecurity
                .authorizeHttpRequests(auth -> auth
                        //.requestMatchers("/login", "/error").permitAll() // TODO: Need if you custom form login
                        .anyRequest().authenticated())

                // TODO: implement default form login
                .formLogin(Customizer.withDefaults());

                // TODO: Custom form login
                // .formLogin(login -> login.loginPage("/login"));

        return httpSecurity.build();
    }

    // Customize Id_Token & Access_Token
    /*@Bean
    OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {

            // TODO: Custom JWT with authorization_code grant type and Authentication
            Authentication authentication = context.getPrincipal();
            if (context.getTokenType().getValue().equals("id_token")) {
                context.getClaims().claim("reksmey1", "Mom Reksmey");
            }

            if (context.getTokenType().getValue().equals("access_token")) {
                context.getClaims().claim("reksmey2", "Access Token");
                Set<String> authorities = authentication.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toSet());
                context.getClaims().claim("authorities", authorities)
                        .claim("user", authentication.getName());
            }

            // TODO: Custom JWT with password grant type and OAuth2ClientAuthenticationToken
            *//*OAuth2ClientAuthenticationToken oAuth2ClientAuthenticationToken = context.getPrincipal();
            CustomUserPassword user = (CustomUserPassword) oAuth2ClientAuthenticationToken.getDetails();
            Set<String> authorities = user.authorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());
            if (context.getTokenType().getValue().equals("access_token")) {
                context.getClaims().claim("authorities", authorities)
                        .claim("user", user.username());
            }*//*

        };
    }*/

    /*@Bean
    OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator() {

        System.out.println("KANGCHI => Start Generate Token");

        NimbusJwtEncoder jwtEncoder = null;

        try {
            jwtEncoder = new NimbusJwtEncoder(jwkSource());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(tokenCustomizer());
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();

        return new DelegatingOAuth2TokenGenerator(
                jwtGenerator, accessTokenGenerator, refreshTokenGenerator
        );
    }*/

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    /*@Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        var keys = keyPairGenerator.generateKeyPair();
        var publicKey = (RSAPublicKey) keys.getPublic();
        var privateKey = keys.getPrivate();

        var rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);

        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }*/


    // ===================================== <IN MEMORY> ===================================== //
    @Bean
    public RegisteredClientRepository registeredClientRepository() {

        var registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("kangchi")
                .clientSecret("{bcrypt}$2a$12$Ar9g2pfdsoX4WlSbn4z2UOqc0ihJgf0Fnt1N4yUFFMImgL/Ww1nwi") // store in secret manager
                .scopes(scopes -> {
                    scopes.add("openid");
                    scopes.add("profile");
                    scopes.add("email");
                    scopes.add("phone");
                    scopes.add("address");
                    //scopes.add("keys.write");
                })
                .redirectUri("http://127.0.0.1:8083/login/oauth2/code/kangchi")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE) // public client - PKCE
                //.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                // grant_type:client_credentials, client_id & client_secret, redirect_uri
                //.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantTypes(
                        grantType -> {
                            grantType.add(AuthorizationGrantType.AUTHORIZATION_CODE);
                            grantType.add(AuthorizationGrantType.REFRESH_TOKEN);
                            grantType.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
                            //grantType.add(new AuthorizationGrantType("custom_password"));
                        }
                )
                .tokenSettings(tokenSettings())
                .clientSettings(clientSettings())
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }


    public TokenSettings tokenSettings() {
        return TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                .accessTokenTimeToLive(Duration.ofDays(1))
                .reuseRefreshTokens(true)
                .refreshTokenTimeToLive(Duration.ofDays(7))
                .build();
    }

    public ClientSettings clientSettings() {
        return ClientSettings.builder()
                .requireAuthorizationConsent(true)
                .requireProofKey(true)
                .build();
    }

}
