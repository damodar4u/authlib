package com.example.authlib.servlets;

import com.example.authlib.config.AuthConfig;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;

public class LoginServlet extends HttpServlet {
    private final AuthConfig config;

    public LoginServlet(AuthConfig config) {
        this.config = config;
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String loginUrl = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize" +
                "?client_id=" + URLEncoder.encode(config.getClientId(), "UTF-8") +
                "&response_type=code" +
                "&redirect_uri=" + URLEncoder.encode(config.getRedirectUri(), "UTF-8") +
                "&scope=openid%20profile%20email";

        resp.sendRedirect(loginUrl);
    }
}
