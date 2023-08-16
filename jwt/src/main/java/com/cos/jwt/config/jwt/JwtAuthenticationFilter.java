package com.cos.jwt.config.jwt;

import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 존재함
// /login  요청해서 username, password 전동하면 (post)
// UsernamePasswordAuthenticationFilter가 동작함
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;


    // /login 요청을 하면 로그인 시도를 위해서 실행 되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        // 1. username, password 받아서
        // 2. 정상인지 로그인 시도를 해본다. authenticationManager로 로그인 시도를 하면
        // PrincipalDetailsService의 loadUserByUsername()메서드가 호출됨
        // 3. PrincipalDetails를 세션에 담아준다(시큐리티가 권한 관리를 위해서 필요)
        // JWT 토큰을 만들어서 응답

        ObjectMapper om = new ObjectMapper();
        try {
            // getInputStream에서 request body의 json 형식의 데이터를 가져온다.
            User user = om.readValue(request.getInputStream(), User.class);

            // 토큰을 만들어준다.
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // 토큰으로 로그인 인증을 진행한다.
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // authentication객체를 session영역에 저장해야하고 그 방법이 return 해주는 것이다.
            // 리턴하는 이유는 권한 관리를 security가 대신 해주기 때문에 편리하게 사용하려고 해주는 것이다.
            // JWT 토큰을 사용하면서 세션을 만들 이유는 없음.
            return  authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    // attemptAuthentication 실행후 인증이 정상적으로 되면 successfulAuthentication가 실행됨
    // 여기서 JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response 해주면 됨.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("로그인 성공 함");
        super.successfulAuthentication(request, response, chain, authResult);
    }
}
