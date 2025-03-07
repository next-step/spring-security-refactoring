package nextstep.security.config;

import jakarta.servlet.Filter;
import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.config.configurer.AuthorizeHttpRequestsConfigurer;
import nextstep.security.config.configurer.CsrfConfigurer;
import nextstep.security.config.configurer.FormLoginConfigurer;
import nextstep.security.config.configurer.HttpBasicConfigurer;
import nextstep.security.config.configurer.OAuth2LoginConfigurer;
import nextstep.security.config.configurer.SecurityConfigurer;
import nextstep.security.config.configurer.SecurityContextConfigurer;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class HttpSecurity {
    private final LinkedHashMap<Class<? extends SecurityConfigurer>, SecurityConfigurer> configurers = new LinkedHashMap<>();
    private List<Filter> filters = new ArrayList<>();
    private final Map<Class<?>, Object> sharedObjects = new HashMap<>();

    public HttpSecurity(AuthenticationManager authenticationManager, Map<Class<?>, Object> sharedObjects) {
        setSharedObject(AuthenticationManager.class, authenticationManager);

        for (Map.Entry<Class<?>, Object> entry : sharedObjects.entrySet()) {
            setSharedObject((Class<Object>) entry.getKey(), entry.getValue());
        }
    }

    public <C> C getSharedObject(Class<C> sharedType) {
        return (C) this.sharedObjects.get(sharedType);
    }

    public <C> void setSharedObject(Class<C> sharedType, C object) {
        this.sharedObjects.put(sharedType, object);
    }

    public SecurityFilterChain build() {
        init();
        configure();
        return new DefaultSecurityFilterChain(filters);
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

    public void addFilter(final Filter filter) {
        this.filters.add(filter);
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
}
