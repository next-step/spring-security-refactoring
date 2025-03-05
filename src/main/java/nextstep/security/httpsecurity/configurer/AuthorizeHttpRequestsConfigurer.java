package nextstep.security.httpsecurity.configurer;

import nextstep.security.access.RequestMatcher;
import nextstep.security.access.RequestMatcherEntry;
import nextstep.security.authorization.AuthorizationFilter;
import nextstep.security.authorization.AuthorizationManager;
import nextstep.security.authorization.RequestMatcherDelegatingAuthorizationManager;
import nextstep.security.httpsecurity.HttpSecurity;

import java.util.ArrayList;
import java.util.List;

public class AuthorizeHttpRequestsConfigurer implements SecurityConfigurer {
    private List<RequestMatcherEntry<AuthorizationManager>> mappings = new ArrayList<>();

    @Override
    public void configure(HttpSecurity http) {
        AuthorizationFilter filter = new AuthorizationFilter(new RequestMatcherDelegatingAuthorizationManager(mappings));
        http.addFilter(filter);
    }

    public AuthorizeHttpRequestsConfigurer addEntry(RequestMatcher requestMatcher, AuthorizationManager manager) {
        mappings.add(new RequestMatcherEntry<>(requestMatcher, manager));
        return this;
    }

    @Override
    public void init(HttpSecurity http) {

    }
}
