package nextstep.security.builder;


import jakarta.servlet.Filter;
import nextstep.oauth2.registration.ClientRegistrationRepository;
import nextstep.security.access.hierarchicalroles.RoleHierarchy;
import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.config.DefaultSecurityFilterChain;
import nextstep.security.config.SecurityFilterChain;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Supplier;

public class HttpSecurity {
    private final LinkedHashMap<Class<? extends SecurityConfigurer>, SecurityConfigurer> configurers = new LinkedHashMap<>();
    private final Map<Class<?>, Object> sharedObjects = new HashMap<>();
    private final SecurityFilterOrderRegistration securityFilterOrderRegistration = new SecurityFilterOrderRegistration();

    public HttpSecurity(AuthenticationManager authenticationManager) {
        setSharedObject(AuthenticationManager.class, authenticationManager);
    }

    public void setSharedObject(Class<?> key, Object value) {
        sharedObjects.put(key, value);
    }


    public SecurityFilterChain build() {
        init();
        configure();
        return new DefaultSecurityFilterChain(securityFilterOrderRegistration.getFilters());
    }

    private void init() {
        for (SecurityConfigurer configurer : this.configurers.values()) {
            configurer.init(this);
        }
    }

    private void configure() {
        for (SecurityConfigurer configurer : this.configurers.values()) {
            configurer.configure(this);
        }
    }

    public HttpSecurity csrf(Customizer<CsrfConfigurer> csrfCustomizer) {
        csrfCustomizer.customize(getOrApply(CsrfConfigurer.class, CsrfConfigurer::new));

        return HttpSecurity.this;
    }

    public HttpSecurity httpBasic(Customizer<HttpBasicConfigurer> httpBasicConfigureCustomizer) {
        final HttpBasicConfigurer httpBasicConfigurer = getOrApply(HttpBasicConfigurer.class, () -> {
            AuthenticationManager authenticationManager = getSharedObjects(AuthenticationManager.class);
            return new HttpBasicConfigurer(authenticationManager);
        });

        httpBasicConfigureCustomizer.customize(httpBasicConfigurer);

        return HttpSecurity.this;
    }


    public HttpSecurity formLogin(Customizer<FormLoginConfigurer> formLoginConfigureCustomizer) {
        final FormLoginConfigurer formLoginConfigurer = getOrApply(FormLoginConfigurer.class, () ->
                new FormLoginConfigurer(getSharedObjects(AuthenticationManager.class))
        );

        formLoginConfigureCustomizer.customize(formLoginConfigurer);

        return HttpSecurity.this;
    }

    public HttpSecurity authorizeHttpRequests(Customizer<AuthorizationConfigurer> authenticationManager) {
        AuthorizationConfigurer authorizationConfigurer = getOrApply(AuthorizationConfigurer.class, () ->
                new AuthorizationConfigurer(getSharedObjects(RoleHierarchy.class))
        );

        authenticationManager.customize(authorizationConfigurer);

        return HttpSecurity.this;
    }

    public HttpSecurity securityContext(Customizer<SecurityContextConfigurer> securityContextCustomizer) {
        securityContextCustomizer.customize(getOrApply(SecurityContextConfigurer.class, SecurityContextConfigurer::new));

        return HttpSecurity.this;
    }

    public HttpSecurity oauth2Login(Customizer<OAuth2Configurer> oauth2ConfigurerCustomizer) {
        final OAuth2Configurer oAuth2Configurer = getOrApply(OAuth2Configurer.class, () -> {
            ClientRegistrationRepository clientRegistrationRepository = getSharedObjects(ClientRegistrationRepository.class);
            AuthenticationManager authenticationManager = getSharedObjects(AuthenticationManager.class);

            return new OAuth2Configurer(clientRegistrationRepository, authenticationManager);
        });

        oauth2ConfigurerCustomizer.customize(oAuth2Configurer);

        return HttpSecurity.this;
    }

    public <T> T getSharedObjects(Class<T> key) {
        return (T) sharedObjects.get(key);
    }

    private <T extends SecurityConfigurer> T getOrApply(Class<T> configurerClass, Supplier<T> configurerSupplier) {
        return (T) this.configurers.computeIfAbsent(configurerClass, key -> configurerSupplier.get());
    }


    public void addFilter(Filter filter) {
        this.securityFilterOrderRegistration.addFilter(filter);
    }

}
