package nextstep.security.csrf;

import jakarta.servlet.http.HttpServletRequest;
import nextstep.security.access.RequestMatcher;

import java.util.Set;

public class DefaultCsrfRequestMatcher implements RequestMatcher {
    private final Set<String> allowedMethods = Set.of("GET", "HEAD", "TRACE", "OPTIONS");

    @Override
    public boolean matches(final HttpServletRequest request) {
        return !allowedMethods.contains(request.getMethod());
    }
}
