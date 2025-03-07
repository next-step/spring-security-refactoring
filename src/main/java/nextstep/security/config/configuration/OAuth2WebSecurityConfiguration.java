package nextstep.security.config.configuration;

import nextstep.oauth2.registration.ClientRegistrationRepository;
import nextstep.oauth2.web.OAuth2AuthorizedClientRepository;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@ConditionalOnBean(ClientRegistrationRepository.class)
public class OAuth2WebSecurityConfiguration {
    @Bean
    @ConditionalOnMissingBean(OAuth2AuthorizedClientRepository.class)
    OAuth2AuthorizedClientRepository authorizedClientRepository() {
        return new OAuth2AuthorizedClientRepository();
    }
}
