package nextstep.autoconfigure;

import nextstep.security.access.*;
import nextstep.security.csrf.CsrfFilter;
import nextstep.security.csrf.CsrfTokenRepository;
import nextstep.security.csrf.DefaultCsrfRequestMatcher;
import nextstep.security.csrf.HttpSessionCsrfTokenRepository;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class CsrfConfigurer extends AbstractFilterConfigurer<CsrfConfigurer> {

    private List<String> ignoringRequestUrl;
    private CsrfTokenRepository DEFAULT_CSRF_REPOSITORY = new HttpSessionCsrfTokenRepository();

    @Override
    public void init(HttpSecurity httpSecurity) {

    }

    @Override
    protected void doConfigure(final HttpSecurity httpSecurity) {
        var filter = new CsrfFilter(DEFAULT_CSRF_REPOSITORY);
        RequestMatcher ignoringRequestMatchers = createRequestMatchers();
        if (ignoringRequestMatchers != null) {
            filter.setRequestMatcher(ignoringRequestMatchers);
        }
        httpSecurity.addFilter(filter);
    }

    private RequestMatcher createRequestMatchers() {
        var defaultMatcher = new DefaultCsrfRequestMatcher();
        if (ignoringRequestUrl == null || ignoringRequestUrl.isEmpty()) {
            return defaultMatcher;
        }
        var requestMatchers = new ArrayList<RequestMatcher>(ignoringRequestUrl.stream()
                .map(PathRequestMatcher::new)
                .toList());
        return new AndRequestMatcher(defaultMatcher,
                new NegatedRequestMatcher(new OrRequestMatcher(requestMatchers)));
    }

    public CsrfConfigurer ignoringRequestMatchers(String... requestUrls) {
        this.ignoringRequestUrl = Arrays.stream(requestUrls).toList();
        return this;
    }


}
