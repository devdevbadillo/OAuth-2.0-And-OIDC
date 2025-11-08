package com.outh2.authorization.controller;

import com.outh2.authorization.service.ISpotifyClientService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/github")
public class SpotifyOAuthController {

    private final ISpotifyClientService spotifyService;

    public SpotifyOAuthController(ISpotifyClientService gitHubService) {
        this.spotifyService = gitHubService;
    }

    @GetMapping("/token")
    public ResponseEntity<Map<String, String>> getToken() {
        String token = spotifyService.getAccessToken();
        if (token != null) {
            return ResponseEntity.ok(Map.of("access_token", token));
        }
        return ResponseEntity.status(500).body(
                Map.of("error", "No se pudo obtener el token"));
    }
}
