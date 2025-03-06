package nextstep.security.config.configurer;

import nextstep.oauth2.registration.ClientRegistrationRepository;
import nextstep.oauth2.web.OAuth2AuthorizationRequestRedirectFilter;
import nextstep.oauth2.web.OAuth2AuthorizedClientRepository;
import nextstep.oauth2.web.OAuth2LoginAuthenticationFilter;
import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.config.HttpSecurity;
import org.springframework.context.ApplicationContext;

public class OAuth2LoginConfigurer implements SecurityConfigurer {
    @Override
    public void init(final HttpSecurity http) {
    }

    @Override
    public void configure(final HttpSecurity http) {
        final ClientRegistrationRepository clientRegistrationRepository = findSharedOrContextBean(http, ClientRegistrationRepository.class);
        final AuthenticationManager authenticationManager = findSharedOrContextBean(http, AuthenticationManager.class);
        final OAuth2AuthorizedClientRepository authorizedClientRepository = findSharedOrContextBean(http, OAuth2AuthorizedClientRepository.class);

        OAuth2AuthorizationRequestRedirectFilter authorizationRequestFilter =
                new OAuth2AuthorizationRequestRedirectFilter(clientRegistrationRepository);
        http.addFilter(authorizationRequestFilter);


        final OAuth2LoginAuthenticationFilter oAuth2LoginAuthenticationFilter = new OAuth2LoginAuthenticationFilter(clientRegistrationRepository, authorizedClientRepository, authenticationManager);
        http.addFilter(oAuth2LoginAuthenticationFilter);
    }

    private static <T> T findSharedOrContextBean(HttpSecurity http, Class<T> beanType) {
        final T sharedObject = http.getSharedObject(beanType);
        if (sharedObject != null) {
            return sharedObject;
        }

        return http.getSharedObject(ApplicationContext.class).getBean(beanType);
    }
}
