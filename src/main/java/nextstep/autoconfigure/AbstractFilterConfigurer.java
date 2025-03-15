package nextstep.autoconfigure;

public abstract class AbstractFilterConfigurer<T extends AbstractFilterConfigurer<T>> implements SecurityConfigurer {

    private boolean disable = false;

    @Override
    public void configure(final HttpSecurity httpSecurity) {
        if (disable) {
            httpSecurity.removeConfigurers(this.getClass());
            return;
        }
        doConfigure(httpSecurity);
    }

    protected abstract void doConfigure(final HttpSecurity httpSecurity);

    public T disable() {
        this.disable = true;
        return (T) this;
    }

}
