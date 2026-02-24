package com.example.test_security.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.stream.Collectors;

@Service
public class TokenService {

    private final JwtEncoder encoder;

    @Value("${app.jwt.expiration}")
    private Long expiration;

    public TokenService(JwtEncoder encoder) {
        this.encoder = encoder;
    }

    public String generateToken(Authentication authentication) {
        Instant now = Instant.now();

        // 1. On récupère les rôles de l'utilisateur (ex: ROLE_USER, ROLE_ADMIN)
        String scope = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));

        // 2. On prépare les informations (Claims)
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")                     // Qui a émis le token
                .issuedAt(now)                      // Heure de création
                .expiresAt(now.plus(expiration, ChronoUnit.MILLIS)) // Heure d'expiration
                .subject(authentication.getName())  // Le nom de l'utilisateur
                .claim("scope", scope)              // Ses rôles
                .build();

        // 3. On demande à l'encodeur de signer tout ça avec l'algorithme HS256
        var encoderParameters = JwtEncoderParameters.from(
                JwsHeader.with(MacAlgorithm.HS256).build(),
                claims
        );

        return this.encoder.encode(encoderParameters).getTokenValue();
    }
}