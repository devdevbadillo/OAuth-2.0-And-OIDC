package com.outh2.authorization.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.Base64;
import java.util.Map;

@Service
public class SpotifyClientServiceImpl implements ISpotifyClientService {

    @Value("${spring.security.oauth2.client.registration.spotify.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.spotify.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.provider.spotify.token-uri}")
    private static String TOKEN_URL;

    private final RestTemplate restTemplate = new RestTemplate();

    @Override
    public String getAccessToken() {
        String credentials = clientId + ":" + clientSecret;
        String encodedCredentials = Base64.getEncoder()
                .encodeToString(credentials.getBytes());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set("Authorization", "Basic " + encodedCredentials);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "client_credentials");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        var response = restTemplate.postForEntity(TOKEN_URL, request, Map.class);
        if ( response.getBody() != null && response.getBody().containsKey("access_token") ) {
            return (String) response.getBody().get("access_token");
        }

        throw new RestClientException("No se pudo obtener el token");
    }
}