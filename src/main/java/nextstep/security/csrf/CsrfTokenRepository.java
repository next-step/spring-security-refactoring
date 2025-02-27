package nextstep.security.csrf;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.util.UUID;

public class CsrfTokenRepository {

    private static final String CSRF_CUSTOM_TOKEN_HEADER = "X-CSRF-TOKEN";
    private static final String CSRF_CUSTOM_TOKEN_PARAMETER = "csrfToken";

    public void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession(true);
        session.setAttribute(CSRF_CUSTOM_TOKEN_HEADER, token);

        response.setHeader(token.headerName(), token.token());
    }

    public CsrfToken loadToken(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }

        Object attribute = session.getAttribute(CSRF_CUSTOM_TOKEN_HEADER);
        if (attribute instanceof CsrfToken csrfToken) {
            return csrfToken;
        }

        return null;
    }

    public CsrfToken generateToken(HttpServletRequest request) {
        String sessionId = request.getSession(true).getId();
        String tokenValue = UUID.randomUUID().toString() + sessionId.hashCode();
        return new CsrfToken(CSRF_CUSTOM_TOKEN_HEADER, CSRF_CUSTOM_TOKEN_PARAMETER, tokenValue);
    }

}
