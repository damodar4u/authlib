package com.example.authlib.servlets;

import com.example.authlib.config.AuthConfig;
import com.example.authlib.utils.TokenUtils;
import com.example.authlib.utils.ClaimsExtractor;
import com.auth0.jwt.interfaces.Claim;
import com.microsoft.aad.msal4j.IAuthenticationResult;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

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

            // Use TokenUtils to acquire tokens
            IAuthenticationResult authResult = TokenUtils.acquireTokenWithAuthCode(authCode, config);

            // Use ClaimsExtractor to extract claims
            Map<String, Claim> claims = ClaimsExtractor.extractClaims(authResult.idToken());

            // Convert claims to JSON
            StringBuilder jsonBuilder = new StringBuilder("{");
            for (Map.Entry<String, Claim> entry : claims.entrySet()) {
                jsonBuilder.append("\"").append(entry.getKey()).append("\": ")
                        .append("\"").append(entry.getValue().asString()).append("\",");
            }
            jsonBuilder.deleteCharAt(jsonBuilder.length() - 1).append("}");

            // Return claims as JSON response
            resp.setContentType("application/json");
            resp.getWriter().write(jsonBuilder.toString());

        } catch (Exception e) {
            resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            resp.getWriter().write("{\"error\": \"Authentication failure: " + e.getMessage() + "\"}");
        }
    }
}
