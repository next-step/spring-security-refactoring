package nextstep.security.csrf;

import nextstep.security.authorization.AccessDeniedException;

public class InvalidCsrfTokenException extends AccessDeniedException {
    public InvalidCsrfTokenException(final String message) {
        super(message);
    }
}
