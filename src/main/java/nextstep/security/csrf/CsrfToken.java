package nextstep.security.csrf;

import java.io.Serial;
import java.io.Serializable;

public record CsrfToken(
        String headerName,
        String parameterName,
        String token
) implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;
}
