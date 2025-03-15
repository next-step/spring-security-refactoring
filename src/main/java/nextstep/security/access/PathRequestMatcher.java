package nextstep.security.access;

import jakarta.servlet.http.HttpServletRequest;

public class PathRequestMatcher implements RequestMatcher {
    private final String path;

    public PathRequestMatcher(String path) {
        this.path = path;
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        return request.getRequestURI().equals(path);
    }

}
