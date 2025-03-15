package nextstep.autoconfigure;

import jakarta.servlet.Filter;
import nextstep.oauth2.web.OAuth2AuthorizationRequestRedirectFilter;
import nextstep.oauth2.web.OAuth2LoginAuthenticationFilter;
import nextstep.security.authentication.BasicAuthenticationFilter;
import nextstep.security.authentication.UsernamePasswordAuthenticationFilter;
import nextstep.security.authorization.AuthorizationFilter;
import nextstep.security.context.SecurityContextHolderFilter;
import nextstep.security.csrf.CsrfFilter;

import java.util.HashMap;
import java.util.Map;

public class FilterOrderRegistration {
    private final Map<Class<? extends Filter>, Integer> filterToOrder = new HashMap<>();

    public FilterOrderRegistration() {
        Step order = new Step(100, 100);
        filterToOrder.put(CsrfFilter.class, order.next());
        filterToOrder.put(SecurityContextHolderFilter.class, order.next());
        filterToOrder.put(UsernamePasswordAuthenticationFilter.class, order.next());
        filterToOrder.put(BasicAuthenticationFilter.class, order.next());
        filterToOrder.put(OAuth2AuthorizationRequestRedirectFilter.class, order.next());
        filterToOrder.put(OAuth2LoginAuthenticationFilter.class, order.next());
        filterToOrder.put(AuthorizationFilter.class, order.next());
    }

    public Integer getOrder(Class<? extends Filter> clazz) {
        Integer order = filterToOrder.get(clazz);
        if (order == null) {
            return Integer.MAX_VALUE;
        }
        return order;
    }

    public void put(final Filter filter, final int order) {
        filterToOrder.putIfAbsent(filter.getClass(), order);
    }

    private static class Step {
        private int value;
        private final int stepSize;

        Step(int initialValue, int stepSize) {
            this.value = initialValue;
            this.stepSize = stepSize;
        }

        int next() {
            int value = this.value;
            this.value += this.stepSize;
            return value;
        }
    }

}
