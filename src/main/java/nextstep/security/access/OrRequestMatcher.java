package nextstep.security.access;

import jakarta.servlet.http.HttpServletRequest;

import java.util.List;

public class OrRequestMatcher implements RequestMatcher {

    private final List<RequestMatcher> requestMatchers;

    public OrRequestMatcher(final List<RequestMatcher> requestMatchers) {
        this.requestMatchers = requestMatchers;
    }

    @Override
    public boolean matches(final HttpServletRequest request) {
        return requestMatchers.stream().anyMatch(it -> it.matches(request));
    }
}
