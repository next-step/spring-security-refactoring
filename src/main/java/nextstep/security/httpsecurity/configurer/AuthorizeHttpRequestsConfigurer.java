package nextstep.security.httpsecurity.configurer;

import jakarta.servlet.http.HttpServletRequest;
import nextstep.security.access.AnyRequestMatcher;
import nextstep.security.access.MvcRequestMatcher;
import nextstep.security.access.RequestMatcher;
import nextstep.security.access.hierarchicalroles.NullRoleHierarchy;
import nextstep.security.access.hierarchicalroles.RoleHierarchy;
import nextstep.security.authorization.*;
import nextstep.security.httpsecurity.HttpSecurity;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class AuthorizeHttpRequestsConfigurer implements SecurityConfigurer {

    private final AuthorizationManagerRequestMatcherRegistry registry;

    private final RoleHierarchy roleHierarchy;

    public AuthorizeHttpRequestsConfigurer(ApplicationContext context) {
        this.registry = new AuthorizationManagerRequestMatcherRegistry();

        this.roleHierarchy = (context.getBeanNamesForType(RoleHierarchy.class).length > 0)
                ? context.getBean(RoleHierarchy.class) : new NullRoleHierarchy();
    }

    @Override
    public void configure(HttpSecurity http) {
        //        AuthorizationFilter filter = new AuthorizationFilter(new RequestMatcherDelegatingAuthorizationManager(mappings));
        //           http.addFilter(filter);
        AuthorizationManager<HttpServletRequest> authorizationManager = this.registry.createAuthorizationManager();
        AuthorizationFilter authorizationFilter = new AuthorizationFilter(authorizationManager);
        http.addFilter(authorizationFilter);
    }

    //    public AuthorizeHttpRequestsConfigurer addEntry(RequestMatcher requestMatcher, AuthorizationManager manager) {
//        mappings.add(new RequestMatcherEntry<>(requestMatcher, manager));
//        return this;
    private AuthorizationManagerRequestMatcherRegistry addMapping(List<? extends RequestMatcher> matchers, AuthorizationManager manager) {
        for (RequestMatcher matcher : matchers) {
            this.registry.addMapping(matcher, manager);
        }
        return this.registry;
    }

    @Override
    public void init(HttpSecurity http) {

    }

    public AuthorizationManagerRequestMatcherRegistry getRegistry() {
        return this.registry;
    }

    public class AuthorizationManagerRequestMatcherRegistry {

        private final RequestMatcherDelegatingAuthorizationManager.Builder managerBuilder = RequestMatcherDelegatingAuthorizationManager
                .builder();

        private void addMapping(RequestMatcher matcher, AuthorizationManager manager) {
            this.managerBuilder.add(matcher, manager);
        }

        private AuthorizationManager<HttpServletRequest> createAuthorizationManager() {
            return this.managerBuilder.build();
        }

        public AuthorizedUrl requestMatchers(String... patterns) {
            return requestMatchers(null, patterns);
        }

        public AuthorizedUrl anyRequest() {
            return requestMatchers(AnyRequestMatcher.INSTANCE);
        }

        public AuthorizedUrl requestMatchers(HttpMethod method, String... patterns) {
            List<RequestMatcher> matchers = new ArrayList<>();
            for (String pattern : patterns) {
                MvcRequestMatcher mvc = new MvcRequestMatcher(method, pattern);
                matchers.add(mvc);
            }
            return chainRequestMatchers(matchers);
        }

        public AuthorizedUrl requestMatchers(RequestMatcher... requestMatchers) {
            return chainRequestMatchers(Arrays.asList(requestMatchers));
        }

        protected AuthorizedUrl chainRequestMatchers(List<RequestMatcher> requestMatchers) {
            return new AuthorizedUrl(requestMatchers);
        }
    }

    public class AuthorizedUrl {

        private final List<? extends RequestMatcher> matchers;

        private boolean not;

        AuthorizedUrl(List<? extends RequestMatcher> matchers) {
            this.matchers = matchers;
        }

        protected List<? extends RequestMatcher> getMatchers() {
            return this.matchers;
        }

        public AuthorizedUrl not() {
            this.not = true;
            return this;
        }

        public AuthorizationManagerRequestMatcherRegistry permitAll() {
            return access((a, o) -> new AuthorizationDecision(true));
        }

        public AuthorizationManagerRequestMatcherRegistry denyAll() {
            return access((a, o) -> new AuthorizationDecision(false));
        }

        public AuthorizationManagerRequestMatcherRegistry hasRole(String role) {
            return access(new AuthorityAuthorizationManager(roleHierarchy, role));
        }

        public AuthorizationManagerRequestMatcherRegistry authenticated() {
            return access(new AuthenticatedAuthorizationManager());
        }

        public AuthorizationManagerRequestMatcherRegistry access(
                AuthorizationManager manager) {
            return (this.not)
                    ? AuthorizeHttpRequestsConfigurer.this.addMapping(this.matchers, AuthorizationManagers.not(manager))
                    : AuthorizeHttpRequestsConfigurer.this.addMapping(this.matchers, manager);
        }
    }
}

