package nextstep.autoconfigure;

import java.util.List;

public abstract class AbstractAuthenticationFilterConfigurer<T extends AbstractAuthenticationFilterConfigurer<T>> extends AbstractFilterConfigurer<T> {
    private boolean permitAll = false;

    @Override
    public void configure(final HttpSecurity httpSecurity) {
        if (permitAll) {
            updateAccessDefaults(httpSecurity, getAccessDefaultUrls());
        }
        super.configure(httpSecurity);
    }


    private void updateAccessDefaults(final HttpSecurity httpSecurity, List<String> urls) {
        var authorizeHttpRequestsConfigurer = httpSecurity.getSharedObject(AuthorizeHttpRequestsConfigurer.class);
        urls.forEach(it ->
                authorizeHttpRequestsConfigurer.requestMatchers(it).permitAll()
        );
    }

    protected abstract List<String> getAccessDefaultUrls();

    public T permitAll() {
        this.permitAll = true;
        return (T) this;
    }


}
