package nextstep.security.builder;

import jakarta.servlet.Filter;
import nextstep.oauth2.web.OAuth2AuthorizationRequestRedirectFilter;
import nextstep.oauth2.web.OAuth2LoginAuthenticationFilter;
import nextstep.security.authentication.BasicAuthenticationFilter;
import nextstep.security.authentication.UsernamePasswordAuthenticationFilter;
import nextstep.security.authorization.AuthorizationFilter;
import nextstep.security.context.SecurityContextHolderFilter;
import nextstep.security.web.csrf.CsrfFilter;

import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

public enum SecurityFilterOrder {
    CSRF_FILTER(CsrfFilter.class, 0),
    SECURITY_CONTEXT_FILTER(SecurityContextHolderFilter.class, 1),
    FORM_LOGIN_FILTER(UsernamePasswordAuthenticationFilter.class, 2),
    HTTP_BASIC_FILTER(BasicAuthenticationFilter.class, 3),
    AUTHORIZATION_FILTER(AuthorizationFilter.class, 4),
    OAUTH2_REDIRECT_FILTER(OAuth2AuthorizationRequestRedirectFilter.class, 5),
    OAUTH2_LOGIN_FILTER(OAuth2LoginAuthenticationFilter.class, 6);

    private static final Map<Class<? extends Filter>, Integer> mapOfFilterOrders = Arrays.stream(SecurityFilterOrder.values())
            .collect(Collectors.toMap(it -> it.filterClass, it -> it.order));

    private final Class<? extends Filter> filterClass;
    private final int order;

    SecurityFilterOrder(Class<? extends Filter> filterClass, int order) {
        this.filterClass = filterClass;
        this.order = order;
    }

    public int getOrder() {
        return order;
    }

    public static Integer findOrder(Class<? extends Filter> filterClass) {
        return mapOfFilterOrders.get(filterClass);
    }

    public static boolean isSecurityFilter(Class<? extends Filter> filterClass) {
        return SecurityFilterOrder.findOrder(filterClass) != null;
    }
}
