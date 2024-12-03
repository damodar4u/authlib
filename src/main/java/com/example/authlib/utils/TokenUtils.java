package com.example.authlib.utils;

import com.example.authlib.config.AuthConfig;
import com.microsoft.aad.msal4j.*;

import java.net.URI;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ExecutionException;

public class TokenUtils {

    // Acquire token using authorization code flow
    public static String acquireTokenWithAuthCode(String authCode, AuthConfig config) throws Exception {
        ConfidentialClientApplication app = ConfidentialClientApplication.builder(
            config.getClientId(),
            ClientSecret.fromSecret(config.getClientSecret())
        ).build();

        AuthorizationCodeParameters parameters = AuthorizationCodeParameters.builder(
            authCode,
            new URI(config.getRedirectUri())
        ).scopes(Collections.singleton("https://graph.microsoft.com/.default")).build();

        IAuthenticationResult result = app.acquireToken(parameters).get();

        return result.accessToken();
    }

    // Validate ID token and extract claims
    public static Claims extractClaims(String idToken) {
        DecodedJWT jwt = JWT.decode(idToken);
        return jwt.getClaims();
    }
}
