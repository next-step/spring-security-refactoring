package nextstep.security.config;

import jakarta.servlet.Filter;
import nextstep.security.config.configurer.CsrfConfigurer;
import nextstep.security.config.configurer.SecurityConfigurer;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

public class HttpSecurity {
    private final LinkedHashMap<Class<? extends SecurityConfigurer>, SecurityConfigurer> configurers = new LinkedHashMap<>();
    private List<Filter> filters = new ArrayList<>();

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

    public HttpSecurity csrf(Customizer<SecurityConfigurer> csrfCustomizer) {
        csrfCustomizer.customize(getOrApply(new CsrfConfigurer()));
        return HttpSecurity.this;
    }

    public void addFilter(final Filter filter) {
        this.filters.add(filter);
    }

    private SecurityConfigurer getOrApply(SecurityConfigurer configurer) {
        Class<? extends SecurityConfigurer> clazz = configurer.getClass();

        SecurityConfigurer config = this.configurers.get(clazz);
        if (config != null) {
            return config;
        }

        this.configurers.put(clazz, configurer);
        return configurer;
    }
}
