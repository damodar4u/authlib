package com.example.authlib.servlets;

import com.example.authlib.config.AuthConfig;
import com.example.authlib.utils.TokenUtils;
import com.auth0.jwt.interfaces.Claim;
import com.microsoft.aad.msal4j.IAuthenticationResult;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

public class AuthCallbackServlet {
    private final AuthConfig config;

    public AuthCallbackServlet(AuthConfig config) {
        this.config = config;
    }

    public Map<String, Claim> handleCallback(String authCode, HttpServletRequest req, HttpServletResponse resp) throws Exception {
        IAuthenticationResult result = TokenUtils.acquireTokenWithAuthCode(authCode, config);
        return TokenUtils.extractClaims(result.idToken());
    }
}
