package nextstep.security.builder;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.authentication.BasicAuthenticationFilter;
import nextstep.security.authentication.UsernamePasswordAuthenticationFilter;
import nextstep.security.context.SecurityContextHolderFilter;
import nextstep.security.fixture.TestAuthenticationManager;
import org.junit.jupiter.api.DisplayName;

import org.junit.jupiter.api.Test;
import org.springframework.core.annotation.Order;

import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityFilterOrderRegistrationTest {

    private final AuthenticationManager authenticationManager = new TestAuthenticationManager();

    private UsernamePasswordAuthenticationFilter usernamePasswordAuthenticationFilter = new UsernamePasswordAuthenticationFilter(authenticationManager);
    private BasicAuthenticationFilter basicAuthenticationFilter = new BasicAuthenticationFilter(authenticationManager);
    private SecurityContextHolderFilter securityContextHolderFilter = new SecurityContextHolderFilter();
    private MinOrderFIlter minOrderFilter = new MinOrderFIlter();
    private MaxOrderFIlter maxOrderFilter = new MaxOrderFIlter();
    private NotOrderFIlter notOrderFilter = new NotOrderFIlter();

    @Test
    @DisplayName("시큐리티 필터는 기본설정값에 의해 정렬이 된다")
    void getFilters() {
        // given
        SecurityFilterOrderRegistration securityFilterOrderRegistration = new SecurityFilterOrderRegistration();
        securityFilterOrderRegistration.addFilter(usernamePasswordAuthenticationFilter);
        securityFilterOrderRegistration.addFilter(basicAuthenticationFilter);
        securityFilterOrderRegistration.addFilter(securityContextHolderFilter);


        // when
        List<Filter> result = securityFilterOrderRegistration.getFilters();

        // then
        assertThat(result).containsExactly(
                securityContextHolderFilter,
                usernamePasswordAuthenticationFilter,
                basicAuthenticationFilter
        );
    }


    @Test
    @DisplayName("Order 어노테이션에 의해 정렬이 된다")
    void orderAnnotationFilter() {
        SecurityFilterOrderRegistration securityFilterOrderRegistration = new SecurityFilterOrderRegistration();
        securityFilterOrderRegistration.addFilter(maxOrderFilter);
        securityFilterOrderRegistration.addFilter(minOrderFilter);
        securityFilterOrderRegistration.addFilter(notOrderFilter);

        List<Filter> result = securityFilterOrderRegistration.getFilters();

        assertThat(result).containsExactly(
                minOrderFilter,
                notOrderFilter,
                maxOrderFilter
        );
    }

    @Test
    @DisplayName("시큐리티 필터 순서 조합과 Order 어노테이션 조합을 합처서 정렬된다")
    void mixOrderFilter() {
        SecurityFilterOrderRegistration securityFilterOrderRegistration = new SecurityFilterOrderRegistration();
        securityFilterOrderRegistration.addFilter(maxOrderFilter);
        securityFilterOrderRegistration.addFilter(minOrderFilter);
        securityFilterOrderRegistration.addFilter(notOrderFilter);
        securityFilterOrderRegistration.addFilter(usernamePasswordAuthenticationFilter);
        securityFilterOrderRegistration.addFilter(basicAuthenticationFilter);
        securityFilterOrderRegistration.addFilter(securityContextHolderFilter);

        List<Filter> result = securityFilterOrderRegistration.getFilters();

        assertThat(result).containsExactly(
                minOrderFilter,
                securityContextHolderFilter,
                usernamePasswordAuthenticationFilter,
                basicAuthenticationFilter,
                notOrderFilter,
                maxOrderFilter
        );
    }


    @Order(Integer.MIN_VALUE)
    private static class MinOrderFIlter implements Filter {
        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        }
    }

    @Order(Integer.MAX_VALUE)
    private static class MaxOrderFIlter implements Filter {
        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {}
    }

    private static class NotOrderFIlter implements Filter {
        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {}
    }
}
