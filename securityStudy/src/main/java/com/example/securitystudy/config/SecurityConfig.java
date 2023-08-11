package com.example.securitystudy.config;

import com.example.securitystudy.domain.User;
import com.example.securitystudy.handler.Http401Handler;
import com.example.securitystudy.handler.Http403Handler;
import com.example.securitystudy.handler.LoginFailHandler;
import com.example.securitystudy.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;

import static org.springframework.boot.autoconfigure.security.servlet.PathRequest.toH2Console;

@Configuration
@EnableWebSecurity(debug = false)
@RequiredArgsConstructor
public class SecurityConfig {

    private final ObjectMapper objectMapper;

    // 스프링 시큐리티 권한을 무시하는 설정
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring()
                .requestMatchers("/favicon.ico")
                .requestMatchers("/error")
                //.requestMatchers(new AntPathRequestMatcher("/h2-console/**"));
                .requestMatchers(toH2Console()); // h2-console은 제외하도록 설정하기 위한 메서드 제공
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests()
                .requestMatchers("/auth/login").permitAll()
                .requestMatchers("/auth/signup").permitAll()
                .requestMatchers("/user").hasAnyRole("USER","ADMIN")
                //.requestMatchers("/admin").hasRole("ADMIN")
                // 역할과 권한을 2개 동시에 주고 싶을때
                .requestMatchers("/admin")
                    .access(new WebExpressionAuthorizationManager("hasRole('ADMIN') AND hasAuthority('WRITE')"))
                .anyRequest().authenticated()
                .and()
                .formLogin() // 폼 로그인 관련 설정
                    .loginPage("/auth/login")
                    .loginProcessingUrl("/auth/login")
                    .usernameParameter("username")
                    .passwordParameter("password")
                    .defaultSuccessUrl("/")
                    .failureHandler(new LoginFailHandler(objectMapper))
                .and()
                .rememberMe(rm -> rm.rememberMeParameter("remember") // 사용할 파라미터명 설정
                        .rememberMeCookieName("remember-me")  // 쿠키명 설정
                        .alwaysRemember(false)
                        .tokenValiditySeconds(2592000)  // 만료시간 설정 (30일)
                )
                .headers()
                    .frameOptions().disable()
                .and()
                .exceptionHandling(e -> {
                    e.accessDeniedHandler(new Http403Handler(objectMapper));
                    e.authenticationEntryPoint(new Http401Handler(objectMapper));
                })
                // .userDetailsService(useDetailsService()) // 사용자 조회를 위해 만들어준다.
                .csrf(AbstractHttpConfigurer::disable)
                .build();
    }

    @Bean
    public UserDetailsService useDetailsService(UserRepository userRepository) {
        // UserDetailsService 인터페이스 규약메 맞쳐서 구현을 해줘야함. 지금은 InMemory를 이용
//        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
//        UserDetails user = User
//                .withUsername("hodol")
//                .password("1234")
//                .roles("ADMIN")
//                .build();
//
//        manager.createUser(user);
//        return manager;


        return username -> {
            User user = userRepository.findByEmail(username).orElseThrow(() -> new UsernameNotFoundException(username + "을 찾을 수 없습니다."));
            return new UserPrincipal(user);
        };
    }


    // userDetail를 사용하려면 passwordEncoder가 있어야 함.
    @Bean
    public PasswordEncoder passwordEncoder() {
        // 테스트로 암호화하지 않은 인코더 설정
        // return NoOpPasswordEncoder.getInstance();

         return new BCryptPasswordEncoder();

//        return new SCryptPasswordEncoder(
//                16,
//                8,
//                1,
//                32,
//                64
//        );
    }
}

