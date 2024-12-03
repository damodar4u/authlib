package com.example.authlib.utils;

import com.example.authlib.config.AuthConfig;
import com.example.authlib.models.TokenResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.message.BasicNameValuePair;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class TokenUtils {
    public static TokenResponse exchangeAuthCodeForTokens(String authCode, AuthConfig config) throws IOException {
        HttpPost post = new HttpPost("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token");

        List<BasicNameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("client_id", config.getClientId()));
        params.add(new BasicNameValuePair("client_secret", config.getClientSecret()));
        params.add(new BasicNameValuePair("code", authCode));
        params.add(new BasicNameValuePair("redirect_uri", config.getRedirectUri()));
        params.add(new BasicNameValuePair("grant_type", "authorization_code"));

        post.setEntity(new UrlEncodedFormEntity(params));

        try (CloseableHttpClient client = HttpClients.createDefault();
             CloseableHttpResponse response = client.execute(post)) {

            ObjectMapper mapper = new ObjectMapper();
            return mapper.readValue(response.getEntity().getContent(), TokenResponse.class);
        }
    }
}
