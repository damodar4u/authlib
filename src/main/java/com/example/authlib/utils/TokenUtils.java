package com.example.authlib.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.microsoft.aad.msal4j.*;
import com.example.authlib.config.AuthConfig; // Ensure proper import of AuthConfig

import java.net.URI;
import java.util.Collections;
import java.util.Map;

public class TokenUtils {

    // Acquire token using authorization code flow
    public static IAuthenticationResult acquireTokenWithAuthCode(String authCode, AuthConfig config) throws Exception {
        // Fix: Use ClientCredentialFactory to create a client secret
        ConfidentialClientApplication app = ConfidentialClientApplication.builder(
            config.getClientId(),
            ClientCredentialFactory.createFromSecret(config.getClientSecret()) // Correct usage for MSAL4J
        ).build();

        AuthorizationCodeParameters parameters = AuthorizationCodeParameters.builder(
            authCode,
            new URI(config.getRedirectUri())
        ).scopes(Collections.singleton("openid profile email")).build();

        return app.acquireToken(parameters).get(); // Acquire token with authorization code flow
    }

    // Extract claims from the ID token
    public static Map<String, Claim> extractClaims(String idToken) {
        // Decode and return claims from the JWT ID token
        DecodedJWT jwt = JWT.decode(idToken);
        return jwt.getClaims();
    }
}
