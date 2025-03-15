package nextstep.security.csrf;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import nextstep.security.authorization.AccessDeniedException;
import org.springframework.http.HttpStatus;

public class DefaultAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(final HttpServletRequest request, final HttpServletResponse response, final AccessDeniedException exception) {
        if (response.isCommitted()) {
            return;
        }
        response.setStatus(HttpStatus.FORBIDDEN.value());
    }
}
