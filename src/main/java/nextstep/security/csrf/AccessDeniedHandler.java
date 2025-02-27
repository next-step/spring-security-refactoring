package nextstep.security.csrf;

import jakarta.servlet.http.HttpServletResponse;
import nextstep.security.authorization.AccessDeniedException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpStatus;

import java.io.IOException;

public class AccessDeniedHandler {

    private static final Log log = LogFactory.getLog(AccessDeniedHandler.class);

    public void onAccessFailure(HttpServletResponse response, AccessDeniedException exception) throws IOException {
        log.error(exception);
        response.sendError(HttpStatus.FORBIDDEN.value(), HttpStatus.FORBIDDEN.getReasonPhrase());
    }
}
