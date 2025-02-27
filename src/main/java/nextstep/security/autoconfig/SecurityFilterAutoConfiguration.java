package nextstep.security.autoconfig;

import org.springframework.boot.web.servlet.DelegatingFilterProxyRegistrationBean;
import org.springframework.context.annotation.Bean;

public class SecurityFilterAutoConfiguration {

    private static final String DEFAULT_FILTER_NAME = "springSecurityFilterChain";

    @Bean
    public DelegatingFilterProxyRegistrationBean securityFilterChainRegistration() {
        return new DelegatingFilterProxyRegistrationBean(DEFAULT_FILTER_NAME);
    }
}
