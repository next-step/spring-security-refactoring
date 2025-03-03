package nextstep.security.builder;

import jakarta.servlet.Filter;

public class OrderedFilter {
    private final int order;
    private final Filter filter;

    public OrderedFilter(int order, Filter filter) {
        this.order = order;
        this.filter = filter;
    }

    public int getOrder() {
        return order;
    }

    public Filter getFilter() {
        return filter;
    }
}
