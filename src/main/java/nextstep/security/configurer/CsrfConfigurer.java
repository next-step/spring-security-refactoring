package nextstep.security.configurer;

import nextstep.security.HttpSecurity;
import nextstep.security.access.MvcRequestMatcher;
import nextstep.security.access.RequestMatcher;
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

    public CsrfConfigurer ignoringRequestMatcher(String pattern) {
        MvcRequestMatcher mvc = new MvcRequestMatcher(null, pattern);
        ignoredCsrfProtectionMatchers.add(mvc);
        return this;
    }
}
