package com.ohgiraffers.security.auth.handler;

import com.ohgiraffers.security.auth.model.DetailsUser;
import com.ohgiraffers.security.auth.service.DetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private DetailsService detailsService;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 1. username password Token (사용자가 로그인 요청시 날린 아이디와 비밀번호를 가지고 있는 임시 객체)
        UsernamePasswordAuthenticationToken loginToken = (UsernamePasswordAuthenticationToken) authentication; // 토큰 타입으로 변경
        String username = loginToken.getName();
        String password = (String) loginToken.getCredentials(); // 토큰이 가지고 있는 값 (패스워드 반환)

        // 2. DB에서 username에 해당하는 정보를 조회한다.
        DetailsUser foundUser = (DetailsUser) detailsService.loadUserByUsername(username);

        // 사용자가 입력한 username, password와 아이디의 비밀번호를 비교하는 로직을 수행함
        if (!passwordEncoder.matches(password, foundUser.getPassword())/*두개가 같은지 비교*/) {
            throw new BadCredentialsException("password 가 일치하지 않습니다.");
        }

        // 인증성공 토큰 발행
        return new UsernamePasswordAuthenticationToken(foundUser, password, foundUser.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
