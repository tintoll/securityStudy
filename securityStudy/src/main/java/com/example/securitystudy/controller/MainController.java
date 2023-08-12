package com.example.securitystudy.controller;

import com.example.securitystudy.config.UserPrincipal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class MainController {

    @GetMapping("/")
    public String mainPage() {
        return "메인 페이지입니다.";
    }

    @PreAuthorize("hasRole('ROLE_USER')")
    @GetMapping("/user")
    public String user(@AuthenticationPrincipal UserPrincipal userPrincipal) {
        log.info(userPrincipal.toString());
        return "사용저 페이지입니다.";
    }

    @PreAuthorize("hasRole('ROLE_ADNIN')")
    @GetMapping("/admin")
    public String admin() {
        return "관리자 페이지입니다.";
    }
}
