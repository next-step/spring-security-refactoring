package nextstep.security.builder;

import jakarta.servlet.Filter;
import org.springframework.core.annotation.Order;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class SecurityFilterOrderRegistration {
    private final List<OrderedFilter> filters = new ArrayList<>();

    private int currentFilterOrder = SecurityFilterOrder.values().length + 1;

    public void addFilter(Filter filter) {
        if (SecurityFilterOrder.isSecurityFilter(filter.getClass())) {
            filters.add(new OrderedFilter(SecurityFilterOrder.findOrder(filter.getClass()), filter));
            return;
        }

        Order orderAnnotation = filter.getClass().getAnnotation(Order.class);
        if (orderAnnotation != null) {
            filters.add(new OrderedFilter(orderAnnotation.value(), filter));
            return;
        }

        filters.add(new OrderedFilter(currentFilterOrder, filter));
        currentFilterOrder++;
    }

    public List<Filter> getFilters() {
        return filters.stream()
                .sorted(Comparator.comparingInt(OrderedFilter::getOrder))
                .map(OrderedFilter::getFilter)
                .toList();
    }
}
