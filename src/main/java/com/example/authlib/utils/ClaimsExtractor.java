package com.example.authlib.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Map;

public class ClaimsExtractor {
    public static Map<String, Claim> extractClaims(String idToken) {
        DecodedJWT jwt = JWT.decode(idToken);
        return jwt.getClaims();
    }
}
