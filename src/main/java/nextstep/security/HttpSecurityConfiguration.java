package nextstep.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;

@Configuration
public class HttpSecurityConfiguration {

    private static final String BEAN_NAME_PREFIX = "nextstep.security.";

    private static final String HTTP_SECURITY_BEAN_NAME = BEAN_NAME_PREFIX + "httpSecurity";

    @Bean(HTTP_SECURITY_BEAN_NAME)
    @Scope("prototype")
    HttpSecurity httpSecurity() {
        return new HttpSecurity();
    }
}
