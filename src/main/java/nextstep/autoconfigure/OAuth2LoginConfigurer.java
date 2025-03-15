package nextstep.autoconfigure;

import nextstep.oauth2.registration.ClientRegistrationRepository;
import nextstep.oauth2.web.OAuth2AuthorizationRequestRedirectFilter;
import nextstep.oauth2.web.OAuth2AuthorizedClientRepository;
import nextstep.oauth2.web.OAuth2LoginAuthenticationFilter;
import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.context.SecurityContextRepository;

public class OAuth2LoginConfigurer extends AbstractFilterConfigurer<OAuth2LoginConfigurer> {
    @Override
    public void init(final HttpSecurity httpSecurity) {

    }

    @Override
    protected void doConfigure(final HttpSecurity httpSecurity) {
        var repository = httpSecurity.getSharedObject(ClientRegistrationRepository.class);
        var redirectFilter = new OAuth2AuthorizationRequestRedirectFilter(repository);
        httpSecurity.addFilter(redirectFilter);
        var authenticationManager = httpSecurity.getSharedObject(AuthenticationManager.class);
        var filter = new OAuth2LoginAuthenticationFilter(repository, new OAuth2AuthorizedClientRepository(), authenticationManager);

        var contextRepository = httpSecurity.getSharedObject(SecurityContextRepository.class);
        if(contextRepository != null) {
            filter.setSecurityContextRepository(contextRepository);
        }
        httpSecurity.addFilter(filter);
    }

}
