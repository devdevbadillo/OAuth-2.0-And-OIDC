package com.outh2.authorization.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class SpotifyClientServiceImpl implements ISpotifyClientService {

    @Value("${spring.security.oauth2.client.registration.spotify.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.spotify.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.registration.spotify.redirect-uri}")
    private String redirectUri;

    @Value("${spring.security.oauth2.client.provider.spotify.authorization-uri}")
    private String authUri;

    @Value("${spring.security.oauth2.client.provider.spotify.token-uri}")
    private String tokenUri;

    private final RestTemplate restTemplate = new RestTemplate();
    private final Map<String, String> pkceStorage = new ConcurrentHashMap<>();

    @Override
    public String getAccessTokenByClientCredentialsFlow() {
        String credentials = clientId + ":" + clientSecret;
        String encodedCredentials = Base64.getEncoder()
                .encodeToString(credentials.getBytes());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set("Authorization", "Basic " + encodedCredentials);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "client_credentials");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        var response = restTemplate.postForEntity(tokenUri, request, Map.class);
        if ( response.getBody() != null && response.getBody().containsKey("access_token") ) {
            return (String) response.getBody().get("access_token");
        }

        throw new RestClientException("No se pudo obtener el token");
    }

    @Override
    public String getAuthorizationUrlWithPKCE() {
        String codeVerifier = generateCodeVerifier();
        String codeChallenge = generateCodeChallenge(codeVerifier);
        String state = Base64.getUrlEncoder().withoutPadding().encodeToString(generateRandomBytes(16).getBytes());

        pkceStorage.put(state, codeVerifier);

        return UriComponentsBuilder.fromHttpUrl(authUri)
                .queryParam("response_type", "code")
                .queryParam("client_id", clientId)
                .queryParam("scope", "user-read-private user-read-email")
                .queryParam("redirect_uri", redirectUri)
                .queryParam("state", state)
                .queryParam("code_challenge_method", "S256")
                .queryParam("code_challenge", codeChallenge)
                .build().toUriString();
    }

    @Override
    public String exchangeCodeForTokenPKCE(String code, String state) {
        String codeVerifier = pkceStorage.remove(state);
        if (codeVerifier == null) {
            throw new RuntimeException("State inválido o expirado. Posible ataque CSRF.");
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        String credentials = clientId + ":" + clientSecret;
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
        headers.set("Authorization", "Basic " + encodedCredentials);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("code", code);
        params.add("redirect_uri", redirectUri);
        params.add("code_verifier", codeVerifier);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        try {
            var response = restTemplate.postForEntity(tokenUri, request, Map.class);
            if (response.getBody() != null && response.getBody().containsKey("access_token")) {
                return (String) response.getBody().get("access_token");
            }
        } catch (Exception e) {
            throw new RuntimeException("Error al obtener token con PKCE: " + e.getMessage());
        }
        return null;
    }

    private String generateCodeVerifier() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] codeVerifier = new byte[32];
        secureRandom.nextBytes(codeVerifier);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifier);
    }

    private String generateCodeChallenge(String codeVerifier) {
        try {
            byte[] bytes = codeVerifier.getBytes(StandardCharsets.US_ASCII);
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(bytes, 0, bytes.length);
            byte[] digest = messageDigest.digest();
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new RuntimeException("Error generando Code Challenge", e);
        }
    }

    private String generateRandomBytes(int length) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return new String(Base64.getEncoder().encode(bytes));
    }
}