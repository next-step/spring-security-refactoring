package nextstep.security.csrf;

import nextstep.security.authorization.AccessDeniedException;

public class MissingCsrfTokenException extends AccessDeniedException {
    public MissingCsrfTokenException(final String message) {
        super(message);
    }
}
