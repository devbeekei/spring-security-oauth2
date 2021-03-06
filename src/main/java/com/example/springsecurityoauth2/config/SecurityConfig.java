package com.example.springsecurityoauth2.config;


import com.example.springsecurityoauth2.security.*;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
@EnableGlobalMethodSecurity(
        securedEnabled = true,
        jsr250Enabled = true,
        prePostEnabled = true
)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomUserDetailsService customUserDetailsService;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    private final OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;

    @Bean
    public TokenAuthenticationFilter tokenAuthenticationFilter() {
        return new TokenAuthenticationFilter();
    }

    @Bean
    public HttpCookieOAuth2AuthorizationRequestRepository cookieOAuth2AuthorizationRequestRepository() {
        return new HttpCookieOAuth2AuthorizationRequestRepository();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean(BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(customUserDetailsService)
                .passwordEncoder(passwordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .cors()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // ????????? ???????????? ??????
                .and()
                .csrf().disable() // csrf ?????????
                .headers().frameOptions().disable()
                .and()
                .formLogin().disable() // ????????? ??? ?????????
                .httpBasic().disable() // Http basic Auth ???????????? ????????? ???????????? ??????(disable ??? ????????? ????????? ??????)
                .exceptionHandling().authenticationEntryPoint(new RestAuthenticationEntryPoint()) // ??????,????????? ?????? ?????? ?????? ??? ??????
                .and()
                .authorizeRequests()
                .antMatchers("/auth/token", "/oauth2/**").permitAll() // Security ?????? Url
                .anyRequest().authenticated() // ??? ?????? ?????? ?????? ??????
                .and()
                .oauth2Login()
                .authorizationEndpoint().baseUri("/oauth2/authorization") // ?????? ????????? Url
                .authorizationRequestRepository(cookieOAuth2AuthorizationRequestRepository()) // ?????? ????????? ????????? ???????????? ??????
                .and()
                .redirectionEndpoint().baseUri("/oauth2/callback/*") // ?????? ?????? ??? Redirect Url
                .and()
                .userInfoEndpoint().userService(customOAuth2UserService) // ????????? ?????? ????????? ????????? ????????????
                .and()
                .successHandler(oAuth2AuthenticationSuccessHandler) // ?????? ?????? ??? Handler
                .failureHandler(oAuth2AuthenticationFailureHandler); // ?????? ?????? ??? Handler

        http.addFilterBefore(tokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

}