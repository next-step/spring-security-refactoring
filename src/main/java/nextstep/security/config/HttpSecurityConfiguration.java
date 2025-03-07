package nextstep.security.config;

import nextstep.oauth2.registration.ClientRegistrationRepository;
import nextstep.oauth2.web.OAuth2AuthorizedClientRepository;
import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.config.authentication.AuthenticationManagerBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Scope;

import java.util.HashMap;
import java.util.Map;

@Configuration(proxyBeanMethods = false)
@Import({OAuth2ClientRegistrationRepositoryConfiguration.class, OAuth2WebSecurityConfiguration.class})
public class HttpSecurityConfiguration {

    private static final String BEAN_NAME_PREFIX = "nextstep.security.config.HttpSecurityConfiguration.";

    private static final String HTTP_SECURITY_BEAN_NAME = BEAN_NAME_PREFIX + "httpSecurity";

    @Autowired
    private ApplicationContext context;

    @Bean(HTTP_SECURITY_BEAN_NAME)
    @Scope("prototype")
    HttpSecurity httpSecurity(ClientRegistrationRepository clientRegistrationRepository,
                              OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository) throws Exception {
        AuthenticationManagerBuilder authenticationBuilder = new AuthenticationManagerBuilder(context);
        final HttpSecurity httpSecurity = new HttpSecurity(authenticationBuilder, createSharedObjects())
                .securityContext(Customizer.withDefaults());

        httpSecurity.setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
        httpSecurity.setSharedObject(OAuth2AuthorizedClientRepository.class, oAuth2AuthorizedClientRepository);
        return httpSecurity;
    }

    private Map<Class<?>, Object> createSharedObjects() {
        Map<Class<?>, Object> sharedObjects = new HashMap<>();
        sharedObjects.put(ApplicationContext.class, this.context);
        return sharedObjects;
    }
}
