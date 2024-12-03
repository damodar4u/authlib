# authlib


import com.example.authlib.config.AuthConfig;
import com.example.authlib.utils.TokenUtils;
import com.auth0.jwt.interfaces.Claim;
import com.microsoft.aad.msal4j.IAuthenticationResult;

import java.util.Map;

public class TestAuthLib {
    public static void main(String[] args) {
        try {
            // Initialize AuthConfig with your test values
            AuthConfig config = new AuthConfig(
                "your-client-id",
                "your-client-secret",
                "http://localhost:8080/callback"
            );

            // Simulate authorization code (replace with a real one from testing)
            String authCode = "your-authorization-code";

            // Acquire token using the library
            IAuthenticationResult authResult = TokenUtils.acquireTokenWithAuthCode(authCode, config);

            // Print the access token
            System.out.println("Access Token: " + authResult.accessToken());

            // Extract and print claims from the ID token
            Map<String, Claim> claims = TokenUtils.extractClaims(authResult.idToken());
            System.out.println("Claims:");
            for (Map.Entry<String, Claim> entry : claims.entrySet()) {
                System.out.println(entry.getKey() + ": " + entry.getValue().asString());
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
