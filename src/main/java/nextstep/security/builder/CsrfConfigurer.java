package nextstep.security.builder;

import jakarta.servlet.http.HttpServletRequest;
import nextstep.security.access.MvcRequestMatcher;
import nextstep.security.access.RequestMatcher;
import nextstep.security.web.csrf.CsrfFilter;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class CsrfConfigurer implements SecurityConfigurer<CsrfFilter, HttpSecurity> {
    private Set<MvcRequestMatcher> ignoringRequestMatchers = new HashSet<>();

    @Override
    public void init(HttpSecurity builder) {
    }

    @Override
    public void configure(HttpSecurity builder) {
        final CsrfFilter csrfFilter = new CsrfFilter(new DefaultRequiresCsrfMatcher(), ignoringRequestMatchers);
        builder.addFilter(csrfFilter);
    }

    public CsrfConfigurer ignoringRequestMatchers(String... patterns) {
        for (String pattern : patterns) {
            MvcRequestMatcher mvc = new MvcRequestMatcher(null, pattern);
            ignoringRequestMatchers.add(mvc);
        }
        return this;
    }

    private static final class DefaultRequiresCsrfMatcher implements RequestMatcher {

        private final HashSet<String> allowedMethods = new HashSet<>(Arrays.asList("GET", "HEAD", "TRACE", "OPTIONS"));

        @Override
        public boolean matches(HttpServletRequest request) {
            return !this.allowedMethods.contains(request.getMethod());
        }

        @Override
        public String toString() {
            return "CsrfNotRequired " + this.allowedMethods;
        }
    }
}
