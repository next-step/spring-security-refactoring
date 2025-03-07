package nextstep.security.config.configurer;

import nextstep.oauth2.authentication.OAuth2LoginAuthenticationProvider;
import nextstep.oauth2.registration.ClientRegistrationRepository;
import nextstep.oauth2.userinfo.DefaultOAuth2UserService;
import nextstep.oauth2.userinfo.OAuth2UserService;
import nextstep.oauth2.web.OAuth2AuthorizationRequestRedirectFilter;
import nextstep.oauth2.web.OAuth2AuthorizedClientRepository;
import nextstep.oauth2.web.OAuth2LoginAuthenticationFilter;
import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.config.HttpSecurity;
import org.springframework.context.ApplicationContext;

import static nextstep.security.config.Oauth2ConfigurationUtils.findSharedOrContextBean;

public class OAuth2LoginConfigurer implements SecurityConfigurer {
    @Override
    public void init(final HttpSecurity http) {
        OAuth2UserService oauth2UserService = getOAuth2UserService(http);
        OAuth2LoginAuthenticationProvider oauth2LoginAuthenticationProvider = new OAuth2LoginAuthenticationProvider(oauth2UserService);
        http.authenticationProvider(oauth2LoginAuthenticationProvider);
    }

    private OAuth2UserService getOAuth2UserService(HttpSecurity http) {
        ApplicationContext context = http.getSharedObject(ApplicationContext.class);
        OAuth2UserService bean = context.getBean(OAuth2UserService.class);
        return (bean != null) ? bean : new DefaultOAuth2UserService();
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
        oAuth2LoginAuthenticationFilter.setAuthenticationManager(authenticationManager);
        http.addFilter(oAuth2LoginAuthenticationFilter);
    }
}
