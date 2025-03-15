package nextstep.security.csrf;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.UUID;

public class HttpSessionCsrfTokenRepository implements CsrfTokenRepository {

    private final String parameterName = "_csrf";

    private final String headerName = "X-CSRF-TOKEN";

    private final String sessionAttributeName = HttpSessionCsrfTokenRepository.class.getName().concat(".CSRF_TOKEN");

    @Override
    public CsrfToken loadToken(HttpServletRequest request) {
        var session = request.getSession(false);
        if (session == null) {
            return null;
        }
        return (CsrfToken) session.getAttribute(this.sessionAttributeName);
    }

    @Override
    public void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response) {
        if (token == null) {
            var session = request.getSession(false);
            //왜 지우는 걸까?
            if (session != null) {
                session.removeAttribute(this.sessionAttributeName);
            }
            return;
        }

        var session = request.getSession();
        session.setAttribute(this.sessionAttributeName, token);
    }

    @Override
    public CsrfToken generateToken(HttpServletRequest request) {
        return new DefaultCsrfToken(this.headerName, this.parameterName, createNewToken());
    }

    private String createNewToken() {
        return UUID.randomUUID().toString();
    }

}
