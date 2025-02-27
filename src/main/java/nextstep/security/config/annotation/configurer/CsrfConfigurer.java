package nextstep.security.config.annotation.configurer;

import nextstep.security.access.MvcRequestMatcher;
import nextstep.security.access.RequestMatcher;
import nextstep.security.config.annotation.HttpSecurity;
import nextstep.security.csrf.CsrfFilter;

import java.util.HashSet;
import java.util.Set;

public class CsrfConfigurer implements SecurityConfigurer {

    private final Set<RequestMatcher> ignoredCsrfProtectionMatchers = new HashSet<>();

    @Override
    public void init(HttpSecurity http) {
        // 다른 요소가 필요없음
    }

    @Override
    public void configure(HttpSecurity http) {
        CsrfFilter csrfFilter = new CsrfFilter(ignoredCsrfProtectionMatchers);
        http.addFilter(csrfFilter);
    }

    public CsrfConfigurer ignoringRequestMatchers(String... patterns) {
        for (String p : patterns) {
            MvcRequestMatcher mvc = new MvcRequestMatcher(null, p);
            ignoredCsrfProtectionMatchers.add(mvc);
        }
        return this;
    }
}
