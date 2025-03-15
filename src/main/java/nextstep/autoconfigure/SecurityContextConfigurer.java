package nextstep.autoconfigure;

import nextstep.security.context.SecurityContextHolderFilter;
import nextstep.security.context.SecurityContextRepository;

public class SecurityContextConfigurer extends AbstractFilterConfigurer<SecurityContextConfigurer> {

    private SecurityContextRepository securityContextRepository;

    @Override
    public void init(HttpSecurity httpSecurity) {
        if (securityContextRepository != null) {
            httpSecurity.setSharedObject(SecurityContextRepository.class, securityContextRepository);
        }
    }

    @Override
    protected void doConfigure(HttpSecurity httpSecurity) {
        var filter = new SecurityContextHolderFilter();
        if (securityContextRepository != null) {
            filter.setSecurityContextRepository(securityContextRepository);
        }
        httpSecurity.addFilter(filter);
    }

    public SecurityContextConfigurer securityContextRepository(final SecurityContextRepository securityContextRepository) {
        this.securityContextRepository = securityContextRepository;
        return this;
    }

}
