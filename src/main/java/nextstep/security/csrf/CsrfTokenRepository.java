package nextstep.security.csrf;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface CsrfTokenRepository {

    CsrfToken loadToken(HttpServletRequest request);

    void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response);

    CsrfToken generateToken(HttpServletRequest request);

}
