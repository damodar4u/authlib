package com.example.authlib.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.microsoft.aad.msal4j.*;

import java.net.URI;
import java.util.Collections;
import java.util.Map;

public class TokenUtils {

    // Acquire token using authorization code flow
    public static IAuthenticationResult acquireTokenWithAuthCode(String authCode, AuthConfig config) throws Exception {
        ConfidentialClientApplication app = ConfidentialClientApplication.builder(
            config.getClientId(),
            ClientSecret.fromSecret(config.getClientSecret())
        ).build();

        AuthorizationCodeParameters parameters = AuthorizationCodeParameters.builder(
            authCode,
            new URI(config.getRedirectUri())
        ).scopes(Collections.singleton("openid profile email")).build();

        return app.acquireToken(parameters).get();
    }

    // Extract claims from the ID token
    public static Map<String, Claim> extractClaims(String idToken) {
        DecodedJWT jwt = JWT.decode(idToken);
        return jwt.getClaims();
    }
}
