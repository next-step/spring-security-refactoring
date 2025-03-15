package nextstep.autoconfigure;

import jakarta.servlet.*;
import nextstep.oauth2.registration.ClientRegistrationRepository;
import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.config.DefaultSecurityFilterChain;
import nextstep.security.config.SecurityFilterChain;
import org.springframework.context.ApplicationContext;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

public class HttpSecurity {

    private final LinkedHashMap<Class<? extends SecurityConfigurer>, SecurityConfigurer> configurers = new LinkedHashMap<>();
    private final List<OrderedFilter> filters = new ArrayList<>();
    private final Map<Class<?>, Object> sharedObjects = new HashMap<>();

    private final FilterOrderRegistration filterOrderRegistration = new FilterOrderRegistration();

    private final AuthorizeHttpRequestsConfigurer authorizeHttpRequestsConfigurer = new AuthorizeHttpRequestsConfigurer();

    public HttpSecurity(final AuthenticationManager authenticationManager, final ClientRegistrationRepository clientRegistrationRepository, ApplicationContext applicationContext) {
        this.setSharedObject(AuthenticationManager.class, authenticationManager);
        this.setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
        this.setSharedObject(AuthorizeHttpRequestsConfigurer.class, authorizeHttpRequestsConfigurer);
        this.setSharedObject(ApplicationContext.class, applicationContext);
    }

    public SecurityFilterChain build() {
        init();
        configure();
        filters.sort(Comparator.comparingInt(OrderedFilter::getOrder));
        return new DefaultSecurityFilterChain(
                filters.stream()
                        .map(OrderedFilter::getFilter)
                        .collect(Collectors.toList()));
    }

    public HttpSecurity addFilterAfter(Filter filter, Class<? extends Filter> afterFilter) {
        return addFilterAtOffsetOf(filter, 1, afterFilter);
    }

    public HttpSecurity addFilterBefore(Filter filter, Class<? extends Filter> beforeFilter) {
        return addFilterAtOffsetOf(filter, -1, beforeFilter);
    }

    public void addFilter(Filter filter) {
        int order = getFilterOrder(filter.getClass());
        filters.add(new OrderedFilter(filter, order));
    }


    private HttpSecurity addFilterAtOffsetOf(Filter filter, int offset, Class<? extends Filter> registeredFilter) {
        int order = getFilterOrder(registeredFilter) + offset;
        this.filters.add(new OrderedFilter(filter, order));
        this.filterOrderRegistration.put(filter, order);
        return this;
    }

    private int getFilterOrder(Class<? extends Filter> clazz) {
        var order = filterOrderRegistration.getOrder(clazz);
        if (order == null) {
            throw new IllegalArgumentException("filter 순서에 등록되지 않았습니다. addFilterBefore 혹은 addFilterAfter를 호출하세요.");
        }
        return order;
    }

    private void init() {
        for (SecurityConfigurer configurer : this.configurers.values()) {
            configurer.init(this);
        }
    }

    private void configure() {
        List<SecurityConfigurer> configurerList = new ArrayList<>(this.configurers.values());
        for (SecurityConfigurer configurer : configurerList) {
            configurer.configure(this);
        }
    }

    private <T extends SecurityConfigurer> T getOrApply(T configurer) {
        var clazz = configurer.getClass();
        var existedConfigured = this.configurers.get(clazz);
        if (existedConfigured != null) {
            return (T) existedConfigured;
        }
        this.configurers.put(clazz, configurer);
        return configurer;
    }

    public <T> T getSharedObject(final Class<T> clazz) {
        Object obj = sharedObjects.get(clazz);
        return (T) obj;
    }

    public <T> void setSharedObject(final Class<T> clazz, T object) {
        sharedObjects.put(clazz, object);
    }

    public HttpSecurity securityContext(final Customizer<SecurityContextConfigurer> customizer) {
        customizer.customize(getOrApply(new SecurityContextConfigurer()));
        return this;
    }


    public HttpSecurity csrf(final Customizer<CsrfConfigurer> customizer) {
        customizer.customize(getOrApply(new CsrfConfigurer()));
        return this;
    }

    public HttpSecurity formLogin(final Customizer<FormLoginConfigurer> customizer) {
        customizer.customize(getOrApply(new FormLoginConfigurer()));
        return this;
    }

    public HttpSecurity httpBasic(final Customizer<HttpBasicConfigurer> customizer) {
        customizer.customize(getOrApply(new HttpBasicConfigurer()));
        return this;
    }

    public HttpSecurity authorizeHttpRequests(final Customizer<AuthorizeHttpRequestsConfigurer> customizer) {
        customizer.customize(getOrApply(authorizeHttpRequestsConfigurer));
        return this;
    }

    public HttpSecurity oAuth2Login(final Customizer<OAuth2LoginConfigurer> customizer) {
        customizer.customize(getOrApply(new OAuth2LoginConfigurer()));
        return this;
    }

    public void removeConfigurers(Class<? extends SecurityConfigurer> clazz) {
        configurers.remove(clazz);
    }

    private static final class OrderedFilter implements Filter {

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

        public int getOrder() {
            return this.order;
        }

        public Filter getFilter() {
            return filter;
        }
    }

}
