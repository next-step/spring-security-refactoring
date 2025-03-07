package nextstep.security.config.configurer;

import nextstep.security.access.AnyRequestMatcher;
import nextstep.security.access.MvcRequestMatcher;
import nextstep.security.access.RequestMatcher;
import nextstep.security.access.RequestMatcherEntry;
import nextstep.security.access.hierarchicalroles.RoleHierarchy;
import nextstep.security.authorization.AuthenticatedAuthorizationManager;
import nextstep.security.authorization.AuthorityAuthorizationManager;
import nextstep.security.authorization.AuthorizationFilter;
import nextstep.security.authorization.AuthorizationManager;
import nextstep.security.authorization.DenyAllAuthorizationManager;
import nextstep.security.authorization.PermitAllAuthorizationManager;
import nextstep.security.authorization.RequestMatcherDelegatingAuthorizationManager;
import nextstep.security.config.HttpSecurity;
import org.springframework.http.HttpMethod;

import java.util.ArrayList;
import java.util.List;

import static nextstep.security.config.Oauth2ConfigurationUtils.findSharedOrContextBean;

public class AuthorizeHttpRequestsConfigurer implements SecurityConfigurer {
    private final RoleHierarchy roleHierarchy;
    private List<RequestMatcherEntry<AuthorizationManager>> mappings = new ArrayList<>();
    private final AuthorizationManagerRequestMatcherRegistry registry;

    public AuthorizeHttpRequestsConfigurer(final HttpSecurity http) {
        this.registry = new AuthorizationManagerRequestMatcherRegistry();
        this.roleHierarchy = findSharedOrContextBean(http, RoleHierarchy.class);
    }

    @Override
    public void init(final HttpSecurity http) {

    }

    @Override
    public void configure(HttpSecurity http) {
        AuthorizationFilter filter = new AuthorizationFilter(registry.createAuthorizationManager());
        http.addFilter(filter);
    }

    public AuthorizationManagerRequestMatcherRegistry getRegistry() {
        return this.registry;
    }

    private AuthorizationManagerRequestMatcherRegistry addMapping(List<? extends RequestMatcher> matchers,
                                                                  AuthorizationManager manager) {
        for (RequestMatcher matcher : matchers) {
            this.registry.addMapping(matcher, manager);
        }
        return this.registry;
    }

    public final class AuthorizationManagerRequestMatcherRegistry {
        private List<RequestMatcherEntry<AuthorizationManager>> mappings = new ArrayList<>();
        private void addMapping(RequestMatcher matcher, AuthorizationManager manager) {
            this.mappings.add(new RequestMatcherEntry<>(matcher, manager));
        }

        public AuthorizedUrl requestMatchers(final String pattern) {
            return new AuthorizedUrl(new MvcRequestMatcher(HttpMethod.GET, pattern));
        }

        public AuthorizedUrl requestMatchers(final HttpMethod method, final String pattern) {
            return new AuthorizedUrl(new MvcRequestMatcher(method, pattern));
        }

        public AuthorizedUrl anyRequest() {
            return new AuthorizedUrl(AnyRequestMatcher.INSTANCE);
        }

        public AuthorizationManager createAuthorizationManager() {
            return new RequestMatcherDelegatingAuthorizationManager(mappings);
        }
    }

    public class AuthorizedUrl {
        private final List<? extends RequestMatcher> matchers;

        private AuthorizedUrl(RequestMatcher... matchers) {
            this(List.of(matchers));
        }

        private AuthorizedUrl(List<RequestMatcher> matchers) {
            this.matchers = matchers;
        }

        public AuthorizationManagerRequestMatcherRegistry permitAll() {
            return AuthorizeHttpRequestsConfigurer.this.addMapping(this.matchers, new PermitAllAuthorizationManager<>());
        }
        public AuthorizationManagerRequestMatcherRegistry denyAll() {
            return AuthorizeHttpRequestsConfigurer.this.addMapping(this.matchers, new DenyAllAuthorizationManager());
        }

        public AuthorizationManagerRequestMatcherRegistry hasRole(String role) {
            return AuthorizeHttpRequestsConfigurer.this.addMapping(this.matchers, new AuthorityAuthorizationManager(getRoleHierarchy(), role));
        }

        public AuthorizationManagerRequestMatcherRegistry authenticated() {
            return AuthorizeHttpRequestsConfigurer.this.addMapping(this.matchers, new AuthenticatedAuthorizationManager());
        }

        private RoleHierarchy getRoleHierarchy() {
            return AuthorizeHttpRequestsConfigurer.this.roleHierarchy;
        }
    }
}
