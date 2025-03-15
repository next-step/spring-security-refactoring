package nextstep.autoconfigure;

import nextstep.security.access.MvcRequestMatcher;
import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.authentication.UsernamePasswordAuthenticationFilter;
import nextstep.security.context.SecurityContextRepository;
import org.springframework.http.HttpMethod;

import java.util.List;

public class FormLoginConfigurer extends AbstractAuthenticationFilterConfigurer<FormLoginConfigurer> {

    private String loginUrl = "/login";
    
    public FormLoginConfigurer() {
    }

    @Override
    public void init(final HttpSecurity httpSecurity) {

    }

    @Override
    protected void doConfigure(final HttpSecurity httpSecurity) {
        var filter = new UsernamePasswordAuthenticationFilter(httpSecurity.getSharedObject(AuthenticationManager.class));
        filter.setRequestMatcher(new MvcRequestMatcher(HttpMethod.POST, loginUrl));
        var contextRepository = httpSecurity.getSharedObject(SecurityContextRepository.class);
        if(contextRepository != null) {
            filter.setSecurityContextRepository(contextRepository);
        }
        httpSecurity.addFilter(filter);
    }

    public FormLoginConfigurer loginPage(final String loginUrl) {
        this.loginUrl = loginUrl;
        return this;
    }

    @Override
    protected List<String> getAccessDefaultUrls() {
        return List.of(loginUrl);
    }
}
