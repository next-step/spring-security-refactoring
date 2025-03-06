package nextstep.security.config;

import nextstep.oauth2.registration.ClientRegistrationRepository;
import nextstep.oauth2.web.OAuth2AuthorizedClientRepository;
import nextstep.security.authentication.AuthenticationManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Scope;

@Configuration(proxyBeanMethods = false)
@Import({OAuth2ClientRegistrationRepositoryConfiguration.class, OAuth2WebSecurityConfiguration.class})
public class HttpSecurityConfiguration {

    private static final String BEAN_NAME_PREFIX = "nextstep.security.config.HttpSecurityConfiguration.";

    private static final String HTTP_SECURITY_BEAN_NAME = BEAN_NAME_PREFIX + "httpSecurity";

    @Bean(HTTP_SECURITY_BEAN_NAME)
    @Scope("prototype")
    HttpSecurity httpSecurity(AuthenticationManager authenticationManager, ClientRegistrationRepository clientRegistrationRepository,
                              OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository) throws Exception {
        final HttpSecurity httpSecurity = new HttpSecurity(authenticationManager)
                .securityContext(Customizer.withDefaults());

        httpSecurity.setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
        httpSecurity.setSharedObject(OAuth2AuthorizedClientRepository.class, oAuth2AuthorizedClientRepository);
        return httpSecurity;
    }
}
