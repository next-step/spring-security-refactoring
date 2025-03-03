package nextstep.security.builder;

import nextstep.oauth2.registration.ClientRegistrationRepository;
import nextstep.oauth2.web.OAuth2AuthorizationRequestRedirectFilter;
import nextstep.oauth2.web.OAuth2AuthorizationRequestResolver;
import nextstep.oauth2.web.OAuth2AuthorizedClientRepository;
import nextstep.oauth2.web.OAuth2LoginAuthenticationFilter;
import nextstep.security.authentication.AuthenticationManager;

public class OAuth2Configurer implements SecurityConfigurer<OAuth2LoginAuthenticationFilter, HttpSecurity> {
    private static final String DEFAULT_AUTHORIZATION_REQUEST_BASE_URI = "/oauth2/authorization/";
    private final AuthenticationManager authenticationManager;

    private ClientRegistrationRepository clientRegistrationRepository;
    private OAuth2AuthorizedClientRepository authorizedClientRepository;
    private AuthorizationEndpointConfig authorizationEndpointConfig;
    private OAuth2AuthorizationRequestResolver authorizationRequestResolver;

    public OAuth2Configurer(ClientRegistrationRepository clientRegistrationRepository, AuthenticationManager authenticationManager) {
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.authorizedClientRepository = new OAuth2AuthorizedClientRepository();
        this.authenticationManager = authenticationManager;
        this.authorizationEndpointConfig = new AuthorizationEndpointConfig(this);
        this.authorizationRequestResolver = new OAuth2AuthorizationRequestResolver(clientRegistrationRepository, DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
    }

    @Override
    public void init(HttpSecurity builder) {

    }

    @Override
    public void configure(HttpSecurity builder) {
        OAuth2AuthorizationRequestRedirectFilter oAuth2AuthorizationRequestRedirectFilter = new OAuth2AuthorizationRequestRedirectFilter(authorizationRequestResolver);

        OAuth2LoginAuthenticationFilter oAuth2LoginAuthenticationFilter = new OAuth2LoginAuthenticationFilter(
                clientRegistrationRepository,
                authorizedClientRepository,
                authenticationManager
        );

        builder.addFilter(oAuth2AuthorizationRequestRedirectFilter);
        builder.addFilter(oAuth2LoginAuthenticationFilter);
    }

    public OAuth2Configurer clientRegistrationRepository(ClientRegistrationRepository clientRegistrationRepository) {
        this.clientRegistrationRepository = clientRegistrationRepository;
        return this;
    }

    public OAuth2Configurer authorizationEndpoint(Customizer<AuthorizationEndpointConfig> customizer) {
        customizer.customize(authorizationEndpointConfig);
        return this;
    }


    public class AuthorizationEndpointConfig {
        private final OAuth2Configurer configurer;

        public AuthorizationEndpointConfig(OAuth2Configurer configurer) {
            this.configurer = configurer;
        }

        public OAuth2Configurer authorizationRequestResolver(OAuth2AuthorizationRequestResolver resolver) {
            authorizationRequestResolver = resolver;
            return configurer;
        }
    }
}
