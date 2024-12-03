package com.example.authlib.servlets;

import com.example.authlib.config.AuthConfig;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;

public class LoginServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        AuthConfig config = (AuthConfig) getServletContext().getAttribute("authConfig");

        // Construct the Azure AD authorization URL
        String loginUrl = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize" +
                "?client_id=" + URLEncoder.encode(config.getClientId(), "UTF-8") +
                "&response_type=code" +
                "&redirect_uri=" + URLEncoder.encode(config.getRedirectUri(), "UTF-8") +
                "&scope=openid profile email";

        // Redirect the user to Azure AD login page
        resp.sendRedirect(loginUrl);
    }
}
