package com.example.authlib.servlets;

import com.example.authlib.config.AuthConfig;
import com.example.authlib.utils.TokenUtils;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AuthCallbackServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        try {
            AuthConfig config = (AuthConfig) getServletContext().getAttribute("authConfig");
            String authCode = req.getParameter("code");

            if (authCode == null || authCode.isEmpty()) {
                resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                resp.getWriter().write("{\"error\": \"Missing authorization code.\"}");
                return;
            }

            // Use MSAL4J to acquire an access token
            String accessToken = TokenUtils.acquireTokenWithAuthCode(authCode, config);

            // Optionally, validate and extract claims (if using ID token)
            // Claims claims = TokenUtils.extractClaims(idToken);

            // Return the token as JSON
            resp.setContentType("application/json");
            resp.getWriter().write("{\"accessToken\": \"" + accessToken + "\"}");

        } catch (Exception e) {
            resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            resp.getWriter().write("{\"error\": \"Authentication failure: " + e.getMessage() + "\"}");
        }
    }
}
