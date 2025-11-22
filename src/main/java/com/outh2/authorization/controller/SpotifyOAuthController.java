package com.outh2.authorization.controller;

import com.outh2.authorization.service.ISpotifyClientService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.Map;

@RestController
@RequestMapping("/api/spotify")
public class SpotifyOAuthController {

    private final ISpotifyClientService spotifyService;

    public SpotifyOAuthController(ISpotifyClientService spotifyService) {
        this.spotifyService = spotifyService;
    }

    @GetMapping("/client-credentials-flow")
    public ResponseEntity<Map<String, String>> getAccessTokenByClientCredentials() {
        return ResponseEntity.ok(Map.of("access_token", this.spotifyService.getAccessTokenByClientCredentialsFlow()));
    }

    @GetMapping("/auth")
    public void initAuthFlow(HttpServletResponse response) throws IOException {
        String spotifyUrl = spotifyService.getAuthorizationUrlWithPKCE();

        response.sendRedirect(spotifyUrl);
    }

    @GetMapping("/authorization-code-flow")
    public ResponseEntity<Map<String, String>> getAccessTokenByAuthorizationCode(
            @RequestParam String code,
            @RequestParam String state
    ) {
        String token = spotifyService.exchangeCodeForTokenPKCE(code, state);
        return ResponseEntity.ok(Map.of("access_token", token));
    }
}
