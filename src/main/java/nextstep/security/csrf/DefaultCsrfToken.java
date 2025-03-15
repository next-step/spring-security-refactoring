package nextstep.security.csrf;

public class DefaultCsrfToken implements CsrfToken {

    private final String headerName;
    private final String parameterName;
    private final String token;

    public DefaultCsrfToken(String headerName, String parameterName, String token) {
        this.headerName = headerName;
        this.parameterName = parameterName;
        this.token = token;
    }

    @Override
    public String getHeaderName() {
        return this.headerName;
    }

    @Override
    public String getParameterName() {
        return this.parameterName;
    }

    @Override
    public String getToken() {
        return this.token;
    }
}
