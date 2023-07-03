package com.cruddemo.config;

import com.cruddemo.security.CustomOAuth2UserService;
import com.cruddemo.security.CustomUserDetailsService;
import com.cruddemo.security.JWTTokenFilter;
import com.cruddemo.security.oauth.OAuth2FailureHandler;
import com.cruddemo.security.oauth.OAuth2SuccessHandler;
import com.cruddemo.security.oauth.common.HttpCookieOAuth2AuthorizationRequestRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Collections;

@Configuration
@EnableWebSecurity
public class OAuth2Config {

    private final CustomOAuth2UserService customAuth2UserService;
    private final CustomUserDetailsService customUserDetailsService;
    private final OAuth2SuccessHandler oAuth2SuccessHandler;
    private final OAuth2FailureHandler oAuth2FailureHandler;
    private final HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;

    private final JWTTokenFilter jwtTokenFilter;

    public OAuth2Config(CustomOAuth2UserService customAuth2UserService, CustomUserDetailsService customUserDetailsService, OAuth2SuccessHandler oAuth2SuccessHandler, OAuth2FailureHandler oAuth2FailureHandler, HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository, JWTTokenFilter jwtTokenFilter) {
        this.customAuth2UserService = customAuth2UserService;
        this.customUserDetailsService = customUserDetailsService;
        this.oAuth2SuccessHandler = oAuth2SuccessHandler;
        this.oAuth2FailureHandler = oAuth2FailureHandler;
        this.httpCookieOAuth2AuthorizationRequestRepository = httpCookieOAuth2AuthorizationRequestRepository;
        this.jwtTokenFilter = jwtTokenFilter;
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authorizeRequests) ->
                        authorizeRequests
                                .requestMatchers("/login", "/auth/**", "/oauth2/**").permitAll()
                                .anyRequest().authenticated()
                )
                .oauth2Login(o -> o
                        .authorizationEndpoint(authorization -> authorization
                                .baseUri("/oauth2/authorize")
//                                .authorizationRequestRepository(httpCookieOAuth2AuthorizationRequestRepository)
                        )
                        .redirectionEndpoint(redirect -> redirect
                                .baseUri("/oauth2/callback/**")
                        )
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(customAuth2UserService)
                        )
                        .successHandler(oAuth2SuccessHandler)
                        .failureHandler(oAuth2FailureHandler)
                )
                .addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class)
//                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .logout(logoutConfigure -> logoutConfigure.logoutSuccessUrl("/login"));

        return http.build();
    }


    @Bean
    public AuthenticationManager authenticationManagerBean() {
        return new ProviderManager(Collections.singletonList(authenticationProvider()));
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(customUserDetailsService);
        return authenticationProvider;
    }


//    @Autowired
//    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
//        auth.authenticationProvider(authenticationProvider());
//    }


//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http.csrf(csrf -> csrf.disable())
//                .authorizeHttpRequests((authorizeRequests) ->
//                        authorizeRequests
//                                .requestMatchers("/login", "/auth/**").permitAll()
//                                .anyRequest().authenticated()
//                )
////                .oauth2Login(
////                        loginConfigure -> loginConfigure.userInfoEndpoint(uie -> uie.userService(customAuth2UserService))
////                )
//                .oauth2Login(Customizer.withDefaults())
//                .logout(logoutConfigure -> logoutConfigure.logoutSuccessUrl("/login"));
//        return http.build();
//    }
}
