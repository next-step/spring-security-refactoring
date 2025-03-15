package nextstep.security.access;

import jakarta.servlet.http.HttpServletRequest;

public class NegatedRequestMatcher implements RequestMatcher {
    private final RequestMatcher requestMatcher;

    public NegatedRequestMatcher(final RequestMatcher requestMatcher) {
        this.requestMatcher = requestMatcher;
    }

    @Override
    public boolean matches(final HttpServletRequest request) {
        return !requestMatcher.matches(request);
    }
}
