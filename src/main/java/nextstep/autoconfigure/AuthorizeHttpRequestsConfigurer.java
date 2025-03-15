package nextstep.autoconfigure;

import jakarta.servlet.http.HttpServletRequest;
import nextstep.security.access.AnyRequestMatcher;
import nextstep.security.access.PathRequestMatcher;
import nextstep.security.access.RequestMatcher;
import nextstep.security.access.RequestMatcherEntry;
import nextstep.security.access.hierarchicalroles.NullRoleHierarchy;
import nextstep.security.access.hierarchicalroles.RoleHierarchy;
import nextstep.security.authorization.*;
import org.springframework.context.ApplicationContext;

import java.util.ArrayList;
import java.util.List;

public class AuthorizeHttpRequestsConfigurer implements SecurityConfigurer {

    private final List<RequestMatcherEntry<AuthorizationManager<HttpServletRequest>>> requestMatcherEntries = new ArrayList<>();

    private RoleHierarchy roleHierarchy = new NullRoleHierarchy();


    @Override
    public void init(final HttpSecurity httpSecurity) {
        initRoleHierarchy(httpSecurity);
    }

    private void initRoleHierarchy(final HttpSecurity httpSecurity) {
        var context = httpSecurity.getSharedObject(ApplicationContext.class);
        if(context == null) {
            return;
        }
        if(context.getBeanNamesForType(RoleHierarchy.class).length < 1) {
            return;
        }
        this.roleHierarchy = context.getBean(RoleHierarchy.class);
    }

    @Override
    public void configure(final HttpSecurity httpSecurity) {
        var authorizationManager = new RequestMatcherDelegatingAuthorizationManager(requestMatcherEntries);
        var filter = new AuthorizationFilter(authorizationManager);
        httpSecurity.addFilter(filter);
    }

    public AuthorizeBuilder requestMatchers(final RequestMatcher requestMatcher) {
        return new AuthorizeBuilder(this, requestMatcher);
    }

    public AuthorizeBuilder requestMatchers(final String path) {
        return new AuthorizeBuilder(this, new PathRequestMatcher(path));
    }

    public AuthorizeBuilder anyRequest() {
        return new AuthorizeBuilder(this, AnyRequestMatcher.INSTANCE);
    }


    private void addRequestMatcherEntry(final RequestMatcher requestMatcher, final AuthorizationManager<HttpServletRequest> authorizationManager) {
        requestMatcherEntries.add(new RequestMatcherEntry<>(requestMatcher, authorizationManager));
    }

    public static class AuthorizeBuilder {
        private final AuthorizeHttpRequestsConfigurer configurer;
        private final RequestMatcher requestMatcher;

        public AuthorizeBuilder(final AuthorizeHttpRequestsConfigurer configurer, final RequestMatcher requestMatcher) {
            this.configurer = configurer;
            this.requestMatcher = requestMatcher;
        }

        public AuthorizeHttpRequestsConfigurer permitAll() {
            configurer.addRequestMatcherEntry(requestMatcher, new PermitAllAuthorizationManager<>());
            return this.configurer;
        }

        public AuthorizeHttpRequestsConfigurer authenticated() {
            configurer.addRequestMatcherEntry(requestMatcher, new AuthenticatedAuthorizationManager<>());
            return this.configurer;
        }

        public AuthorizeHttpRequestsConfigurer hasAuthority(String authority) {
            configurer.addRequestMatcherEntry(requestMatcher, new AuthorityAuthorizationManager<>(
                    configurer.roleHierarchy,
                    authority));
            return this.configurer;
        }

    }


}
