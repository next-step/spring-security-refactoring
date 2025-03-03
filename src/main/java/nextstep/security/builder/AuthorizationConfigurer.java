package nextstep.security.builder;

import nextstep.security.access.AnyRequestMatcher;
import nextstep.security.access.MvcRequestMatcher;
import nextstep.security.access.RequestMatcher;
import nextstep.security.access.RequestMatcherEntry;
import nextstep.security.access.hierarchicalroles.NullRoleHierarchy;
import nextstep.security.access.hierarchicalroles.RoleHierarchy;
import nextstep.security.authorization.AuthenticatedAuthorizationManager;
import nextstep.security.authorization.AuthorityAuthorizationManager;
import nextstep.security.authorization.AuthorizationFilter;
import nextstep.security.authorization.AuthorizationManager;
import nextstep.security.authorization.DenyAllAuthorizationManager;
import nextstep.security.authorization.PermitAllAuthorizationManager;
import nextstep.security.authorization.RequestMatcherDelegatingAuthorizationManager;
import org.springframework.http.HttpMethod;

import java.util.ArrayList;
import java.util.List;

public class AuthorizationConfigurer implements SecurityConfigurer<AuthorizationFilter, HttpSecurity> {

    private final List<RequestMatcherEntry<AuthorizationManager>> mappings = new ArrayList<>();
    private RoleHierarchy roleHierarchy = new NullRoleHierarchy();

    public AuthorizationConfigurer(RoleHierarchy roleHierarchy) {
        this.roleHierarchy = roleHierarchy;
    }

    @Override
    public void init(HttpSecurity builder) {
    }

    @Override
    public void configure(HttpSecurity builder) {
        AuthorizationFilter authorizationFilter = new AuthorizationFilter(new RequestMatcherDelegatingAuthorizationManager(mappings));
        builder.addFilter(authorizationFilter);
    }

    public AuthorizedEntry requestMatchers(RequestMatcher matcher) {
        return new AuthorizedEntry(matcher);
    }

    public AuthorizedEntry requestMatchers(String url) {
        return requestMatchers(new MvcRequestMatcher(HttpMethod.GET, url));
    }

    public AuthorizedEntry anyRequest() {
        return new AuthorizedEntry(AnyRequestMatcher.INSTANCE);
    }

    public class AuthorizedEntry {
        private final RequestMatcher requestMatcher;

        public AuthorizedEntry(RequestMatcher requestMatcher) {
            this.requestMatcher = requestMatcher;
        }

        public AuthorizedEntry requestMatchers(String url) {
            return requestMatchers(HttpMethod.GET, url);
        }

        public AuthorizedEntry requestMatchers(HttpMethod method, String url) {
            return new AuthorizedEntry(new MvcRequestMatcher(method, url));
        }

        public AuthorizedEntry anyRequest() {
            return new AuthorizedEntry(AnyRequestMatcher.INSTANCE);
        }

        public AuthorizedEntry permitAll() {
            mappings.add(new RequestMatcherEntry<>(requestMatcher, new PermitAllAuthorizationManager()));
            return this;
        }

        public AuthorizedEntry denyAll() {
            mappings.add(new RequestMatcherEntry<>(requestMatcher, new DenyAllAuthorizationManager()));
            return this;
        }

        public AuthorizedEntry hasRole(String role) {
            mappings.add(new RequestMatcherEntry<>(requestMatcher, new AuthorityAuthorizationManager(roleHierarchy, role)));
            return this;
        }

        public AuthorizedEntry authenticated() {
            mappings.add(new RequestMatcherEntry<>(requestMatcher, new AuthenticatedAuthorizationManager()));
            return this;
        }
    }
}
