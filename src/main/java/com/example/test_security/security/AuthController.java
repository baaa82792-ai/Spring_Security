package com.example.test_security.security;

import com.example.test_security.security.TokenService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final TokenService tokenService;

    public AuthController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    // On ajoute HttpServletResponse pour manipuler les headers
    @PostMapping("/login")
    public ResponseEntity<Void> login(Authentication authentication, HttpServletResponse response) {
        String token = tokenService.generateToken(authentication);

        ResponseCookie cookie = ResponseCookie.from("jwt-token", token)
                .httpOnly(true)
                .secure(false) // Mettre à true en production (HTTPS)
                .path("/")
                .maxAge(3600) // 1 heure par exemple
                .sameSite("Lax")
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        return ResponseEntity.ok().build();
    }

}