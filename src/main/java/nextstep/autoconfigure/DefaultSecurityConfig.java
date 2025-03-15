package nextstep.autoconfigure;

import nextstep.oauth2.OAuth2ClientProperties;
import nextstep.oauth2.registration.ClientRegistration;
import nextstep.oauth2.registration.ClientRegistrationRepository;
import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.config.DelegatingFilterProxy;
import nextstep.security.config.FilterChainProxy;
import nextstep.security.config.SecurityFilterChain;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfig {

    private final AuthenticationManager authenticationManager;

    public DefaultSecurityConfig(final AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Bean
    public DelegatingFilterProxy delegatingFilterProxy(List<SecurityFilterChain> securityFilterChains) {
        return new DelegatingFilterProxy(new FilterChainProxy(securityFilterChains));
    }

    @Bean
    @Order(SecurityProperties.BASIC_AUTH_ORDER)
    @ConditionalOnMissingBean({SecurityFilterChain.class})
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) {
        return http
                .formLogin(formLogin ->
                        formLogin.loginPage("/login").permitAll())
                .httpBasic(Customizer.withDefaults())
                .authorizeHttpRequests(it -> it.anyRequest().authenticated())
                .build();
    }


    @Bean
    @ConditionalOnMissingBean({HttpSecurity.class})
    HttpSecurity httpSecurity(ClientRegistrationRepository clientRegistrationRepository, ApplicationContext applicationContext) {
        return new HttpSecurity(authenticationManager, clientRegistrationRepository, applicationContext);
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(OAuth2ClientProperties properties) {
        return new ClientRegistrationRepository(getClientRegistrations(properties));
    }

    private static Map<String, ClientRegistration> getClientRegistrations(OAuth2ClientProperties properties) {
        Map<String, ClientRegistration> clientRegistrations = new HashMap<>();
        properties.getRegistration().forEach((key, value) -> clientRegistrations.put(key,
                getClientRegistration(key, value, properties.getProvider().get(key))));
        return clientRegistrations;
    }

    private static ClientRegistration getClientRegistration(String registrationId,
                                                            OAuth2ClientProperties.Registration registration, OAuth2ClientProperties.Provider provider) {
        return new ClientRegistration(registrationId, registration.getClientId(), registration.getClientSecret(), registration.getRedirectUri(), registration.getScope(), provider.getAuthorizationUri(), provider.getTokenUri(), provider.getUserInfoUri(), provider.getUserNameAttributeName());
    }
}
