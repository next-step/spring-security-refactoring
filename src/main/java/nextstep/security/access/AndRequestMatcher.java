package nextstep.security.access;

import jakarta.servlet.http.HttpServletRequest;

import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.List;

public class AndRequestMatcher implements RequestMatcher {

    private final List<RequestMatcher> requestMatchers;

    public AndRequestMatcher(RequestMatcher... requestMatchers) {
        this.requestMatchers = Arrays.asList(requestMatchers);
    }

    @Override
    public boolean matches(final HttpServletRequest request) {
        return requestMatchers.stream().allMatch(it -> it.matches(request));
    }

}
