package nextstep.security.config.autoconfigure;

import org.springframework.boot.web.servlet.DelegatingFilterProxyRegistrationBean;
import org.springframework.context.annotation.Bean;

public class SecurityFilterAutoConfiguration {

    private static final String DEFAULT_FILTER_NAME = "springSecurityFilterChain";

    @Bean
    public DelegatingFilterProxyRegistrationBean securityFilterChainRegistration() {
        // DelegatingFilterProxy가 생성, 생성되는 DelegatingFilterProxy의 delegate가 되는 빈의 이름이 FilterChainProxy인 "springSecurityFilterChain"
        DelegatingFilterProxyRegistrationBean registration = new DelegatingFilterProxyRegistrationBean(DEFAULT_FILTER_NAME);
        return registration;
    }
}

