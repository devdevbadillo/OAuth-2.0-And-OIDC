package com.outh2.authorization.service;

public interface ISpotifyClientService {

    String getAccessTokenByClientCredentialsFlow();

    String getAuthorizationUrlWithPKCE();

    String exchangeCodeForTokenPKCE(String code, String state);

}