package nextstep.security.config.autoconfigure;

import org.springframework.boot.web.servlet.DelegatingFilterProxyRegistrationBean;
import org.springframework.context.annotation.Bean;

public class SecurityFilterAutoConfiguration {

    private static final String DEFAULT_FILTER_NAME = "springSecurityFilterChain";

    @Bean
    public DelegatingFilterProxyRegistrationBean securityFilterChainRegistration() {
        // Security 설정이 활성화되면 springSecurityFilterChain이라는 필터 빈을 자동으로 생성하고 이 필터를 서블릿 컨테이너에 등록.
        DelegatingFilterProxyRegistrationBean registration = new DelegatingFilterProxyRegistrationBean(DEFAULT_FILTER_NAME);
        return registration;
    }
}

