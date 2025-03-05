package nextstep.security.config;

import nextstep.security.authentication.AuthenticationManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;

@Configuration(proxyBeanMethods = false)
public class HttpSecurityConfiguration {

    private static final String BEAN_NAME_PREFIX = "nextstep.security.config.HttpSecurityConfiguration.";

    private static final String HTTP_SECURITY_BEAN_NAME = BEAN_NAME_PREFIX + "httpSecurity";

    @Bean(HTTP_SECURITY_BEAN_NAME)
    @Scope("prototype")
    HttpSecurity httpSecurity(AuthenticationManager authenticationManager) throws Exception {
        return new HttpSecurity(authenticationManager)
                .securityContext(Customizer.withDefaults());
    }
}
