package nextstep.security.config.configurer;

import nextstep.security.access.MvcRequestMatcher;
import nextstep.security.config.HttpSecurity;
import nextstep.security.web.csrf.CsrfFilter;
import org.springframework.http.HttpMethod;

import java.util.Set;

public class CsrfConfigurer implements SecurityConfigurer {
    @Override
    public void init(HttpSecurity http) {
        http.addFilter(new CsrfFilter(Set.of(new MvcRequestMatcher(HttpMethod.POST, "/login"))));
    }

    @Override
    public void configure(HttpSecurity http) {
    }
}
