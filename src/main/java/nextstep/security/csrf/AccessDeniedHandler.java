package nextstep.security.csrf;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import nextstep.security.authorization.AccessDeniedException;

public interface AccessDeniedHandler {

    void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException exception);
}
