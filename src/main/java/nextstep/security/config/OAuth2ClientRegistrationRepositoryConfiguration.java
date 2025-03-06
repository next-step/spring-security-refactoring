package nextstep.security.config;

import nextstep.oauth2.registration.ClientRegistration;
import nextstep.oauth2.registration.ClientRegistrationRepository;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

@Configuration(proxyBeanMethods = false)
class OAuth2ClientRegistrationRepositoryConfiguration {
    private final nextstep.oauth2.OAuth2ClientProperties oAuth2ClientProperties;

    OAuth2ClientRegistrationRepositoryConfiguration(final nextstep.oauth2.OAuth2ClientProperties oAuth2ClientProperties) {
        this.oAuth2ClientProperties = oAuth2ClientProperties;
    }

    @Bean
    @ConditionalOnMissingBean(ClientRegistrationRepository.class)
    public ClientRegistrationRepository clientRegistrationRepository() {
        Map<String, ClientRegistration> registrations = getClientRegistrations(oAuth2ClientProperties);
        return new ClientRegistrationRepository(registrations);
    }

    private static Map<String, ClientRegistration> getClientRegistrations(nextstep.oauth2.OAuth2ClientProperties properties) {
        Map<String, ClientRegistration> clientRegistrations = new HashMap<>();
        properties.getRegistration().forEach((key, value) -> clientRegistrations.put(key,
                getClientRegistration(key, value, properties.getProvider().get(key))));
        return clientRegistrations;
    }

    private static ClientRegistration getClientRegistration(String registrationId,
                                                            nextstep.oauth2.OAuth2ClientProperties.Registration registration, nextstep.oauth2.OAuth2ClientProperties.Provider provider) {
        return new ClientRegistration(registrationId, registration.getClientId(), registration.getClientSecret(), registration.getRedirectUri(), registration.getScope(), provider.getAuthorizationUri(), provider.getTokenUri(), provider.getUserInfoUri(), provider.getUserNameAttributeName());
    }

}
