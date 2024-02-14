package com.ohgiraffers.security.auth.config;

import com.ohgiraffers.security.auth.filter.CustomAuthenticationFilter;
import com.ohgiraffers.security.auth.handler.CustomAuthFailureHandler;
import com.ohgiraffers.security.auth.handler.CustomAuthSuccessHandler;
import com.ohgiraffers.security.auth.handler.CustomAuthenticationProvider;
import org.hibernate.annotations.Bag;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration // 설정 읽어서 환경 구성
@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableWebSecurity // 시큐리티 설정
public class WebSecurityConfig {

    /**
     * 1. 정적 자원에 대한 인증된 사용자의 접근을 설정하는 메소드
     *
     * @return WebSecurityCustomizer
     * */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        // 요청 리소스가 static resources 를 등록하지 않겠다.
        return web -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    /**
     * 2. security filter chain 설정
     *
     * @return SecurityFilterChain
     * */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // csrf : Cross-Site Request Forgery (교차인증 설정)
        http.csrf(AbstractHttpConfigurer::disable) // 하지 않겠다
                .addFilterBefore(jwtAuthorizationFilter(), BasicAuthenticationFilter.class) // BasicAuthenticationFilter 대신에 jwtAuthorizationFilter 이거로 커스터마이징
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // 세션 만들지 않을거다 선언 (STATELESS)
                .formLogin(form -> form.disable()) // 스프링 시큐리티에서 제공해주는 form을 사용하지 않겠다 선언
                .addFilterBefore(customAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class) // UsernamePasswordAuthenticationFilter 사용자의 정보(아이디,비번)을 받아서 db와 비교해보는 로직
                .httpBasic(basic -> basic.disable());

        return http.build(); // securityFilterChain에 http를 걸어서 설정함
    }

    /**
     * 3. Authentication의 인증 메소드를 제공하는 매니저로 Provider의 인터페이스를 의미한다
     *
     * @return AuthenticationManager
     * */
    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(customAuthenticationProvider());
    }

    /**
     * 4. 사용자의 아이디와 패스워드를 DB와 검증하는 handler이다
     *
     * @return CustomAuthenticationProvider
     * */
    @Bean
    public CustomAuthenticationProvider customAuthenticationProvider() {
        return new CustomAuthenticationProvider();
    }

    /**
     * 5. 비밀번호를 암호화 하는 인코더
     *
     * @return BCryptPasswordEncoder
     * */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 6. 사용자의 인증 요청을 가로채서 로그인 로직을 수행하는 필터
     *
     * @return CustomAuthenticationFilter
     * */
    @Bean
    public CustomAuthenticationFilter customAuthenticationFilter() {
        CustomAuthenticationFilter authenticationFilter = new CustomAuthenticationFilter(authenticationManager());
        authenticationFilter.setFilterProcessesUrl("/login");/* 어떤게 로그인 요청인지 확인해서 가로챔 */
        authenticationFilter.setAuthenticationSuccessHandler(customAuthSuccessHandler());
        authenticationFilter.setAuthenticationFailureHandler(customAuthFailureHandler());

        return customAuthenticationFilter();
    }

    /**
     * 7. spring security 기반의 사용자의 정보가 맞을 경우 결과를 수행하는 handler
     * @return customAuthLoginSuccessHandler
     * */
    @Bean
    public CustomAuthSuccessHandler customAuthSuccessHandler() {
        return new CustomAuthSuccessHandler();
    }

    /**
     * 8. spring security의 사용자 정보가 맞지 않은 경우 수행되는 메서드
     * @return CustomAuthFailureHandler
     * */
    @Bean
    public CustomAuthFailureHandler customAuthFailureHandler() {
        return new CustomAuthFailureHandler();
    }
}
