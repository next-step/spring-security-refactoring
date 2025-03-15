package nextstep.security.csrf;

public interface CsrfToken {
    String getHeaderName();
    String getParameterName();
    String getToken();

}
