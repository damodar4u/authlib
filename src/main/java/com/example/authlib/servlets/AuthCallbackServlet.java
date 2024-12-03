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

            // Exchange authorization code for tokens
            var tokenResponse = TokenUtils.exchangeAuthCodeForTokens(authCode, config);

            // Extract claims from the ID token
            var claims = ClaimsExtractor.extractClaims(tokenResponse.getIdToken());

            // Return claims as JSON response
            resp.setContentType("application/json");
            resp.getWriter().write(new ObjectMapper().writeValueAsString(claims));

        } catch (Exception e) {
            resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            resp.getWriter().write("{\"error\": \"Authentication failure: " + e.getMessage() + "\"}");
        }
    }
}
