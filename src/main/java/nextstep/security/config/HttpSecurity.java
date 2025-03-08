package nextstep.security.config;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.authentication.AuthenticationProvider;
import nextstep.security.config.authentication.AuthenticationManagerBuilder;
import nextstep.security.config.configurer.AuthorizeHttpRequestsConfigurer;
import nextstep.security.config.configurer.CsrfConfigurer;
import nextstep.security.config.configurer.FormLoginConfigurer;
import nextstep.security.config.configurer.HttpBasicConfigurer;
import nextstep.security.config.configurer.OAuth2LoginConfigurer;
import nextstep.security.config.configurer.SecurityConfigurer;
import nextstep.security.config.configurer.SecurityContextConfigurer;
import org.springframework.core.OrderComparator;
import org.springframework.core.Ordered;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class HttpSecurity extends SecurityBuilder<SecurityFilterChain> {
    private final LinkedHashMap<Class<? extends SecurityConfigurer>, SecurityConfigurer> configurers = new LinkedHashMap<>();
    private List<OrderedFilter> filters = new ArrayList<>();
    private FilterOrderRegistration filterOrders = new FilterOrderRegistration();

    public HttpSecurity(AuthenticationManagerBuilder authenticationManagerBuilder, Map<Class<?>, Object> sharedObjects) {
        setSharedObject(AuthenticationManagerBuilder.class, authenticationManagerBuilder);
        for (Map.Entry<Class<?>, Object> entry : sharedObjects.entrySet()) {
            setSharedObject((Class<Object>) entry.getKey(), entry.getValue());
        }
    }

    private DefaultSecurityFilterChain performBuild() {
        this.filters.sort(OrderComparator.INSTANCE);

        List<Filter> sortedFilters = new ArrayList<>(this.filters.size());
        for (Filter filter : this.filters) {
            sortedFilters.add(((OrderedFilter) filter).filter);
        }
        return new DefaultSecurityFilterChain(sortedFilters);
    }

    private void init() {
        for (SecurityConfigurer configurer : this.configurers.values()) {
            configurer.init(this);
        }
    }

    private void beforeConfigure() {
        AuthenticationManager manager = getAuthenticationRegistry().build();
        setSharedObject(AuthenticationManager.class, manager);
    }

    private void configure() {
        for (SecurityConfigurer configurer : this.configurers.values()) {
            configurer.configure(this);
        }
    }

    @Override
    public SecurityFilterChain build() {
        init();
        beforeConfigure();
        configure();
        return performBuild();
    }

    public HttpSecurity addFilter(Filter filter) {
        Integer order = this.filterOrders.getOrder(filter.getClass());
        if (order == null) {
            throw new IllegalArgumentException();
        }
        filters.add(new OrderedFilter(filter, order));
        return this;
    }

    public HttpSecurity authenticationProvider(AuthenticationProvider authenticationProvider) {
        getAuthenticationRegistry().authenticationProvider(authenticationProvider);
        return this;
    }

    private AuthenticationManagerBuilder getAuthenticationRegistry() {
        return getSharedObject(AuthenticationManagerBuilder.class);
    }

    public HttpSecurity csrf(Customizer<CsrfConfigurer> csrfCustomizer) {
        csrfCustomizer.customize(getOrApply(new CsrfConfigurer()));
        return HttpSecurity.this;
    }

    public HttpSecurity httpBasic(Customizer<HttpBasicConfigurer> httpBasicCustomizer) {
        httpBasicCustomizer.customize(getOrApply(new HttpBasicConfigurer()));
        return HttpSecurity.this;
    }

    public HttpSecurity formLogin(Customizer<FormLoginConfigurer> httpBasicCustomizer) {
        httpBasicCustomizer.customize(getOrApply(new FormLoginConfigurer()));
        return HttpSecurity.this;
    }


    public HttpSecurity oauth2Login(final Customizer<OAuth2LoginConfigurer> httpBasicCustomizer) {
        httpBasicCustomizer.customize(getOrApply(new OAuth2LoginConfigurer()));
        return HttpSecurity.this;
    }

    public HttpSecurity securityContext(Customizer<SecurityContextConfigurer> securityContextCustomizer) {
        securityContextCustomizer.customize(getOrApply(new SecurityContextConfigurer()));
        return HttpSecurity.this;
    }

    public HttpSecurity authorizeHttpRequests(Customizer<AuthorizeHttpRequestsConfigurer.AuthorizationManagerRequestMatcherRegistry>
                                                      authorizeHttpRequestsCustomizer) {
        authorizeHttpRequestsCustomizer.customize(getOrApply(new AuthorizeHttpRequestsConfigurer(this)).getRegistry());
        return HttpSecurity.this;
    }

    private <C extends SecurityConfigurer> C getOrApply(C configurer) {
        Class<? extends SecurityConfigurer> clazz = configurer.getClass();

        C config = (C) this.configurers.get(clazz);
        if (config != null) {
            return config;
        }

        this.configurers.put(clazz, configurer);
        return configurer;
    }

    private static final class OrderedFilter implements Ordered, Filter {

        private final Filter filter;

        private final int order;

        private OrderedFilter(Filter filter, int order) {
            this.filter = filter;
            this.order = order;
        }

        @Override
        public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
                throws IOException, ServletException {
            this.filter.doFilter(servletRequest, servletResponse, filterChain);
        }

        @Override
        public int getOrder() {
            return this.order;
        }

        @Override
        public String toString() {
            return "OrderedFilter{" + "filter=" + this.filter + ", order=" + this.order + '}';
        }
    }
}
