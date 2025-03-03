package nextstep.security.builder;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import nextstep.oauth2.web.OAuth2AuthorizationRequestRedirectFilter;
import nextstep.oauth2.web.OAuth2LoginAuthenticationFilter;
import nextstep.security.authentication.BasicAuthenticationFilter;
import nextstep.security.authentication.UsernamePasswordAuthenticationFilter;
import nextstep.security.authorization.AuthorizationFilter;
import nextstep.security.context.SecurityContextHolderFilter;
import nextstep.security.web.csrf.CsrfFilter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.util.stream.Stream;

import static nextstep.security.builder.SecurityFilterOrder.AUTHORIZATION_FILTER;
import static nextstep.security.builder.SecurityFilterOrder.CSRF_FILTER;
import static nextstep.security.builder.SecurityFilterOrder.FORM_LOGIN_FILTER;
import static nextstep.security.builder.SecurityFilterOrder.HTTP_BASIC_FILTER;
import static nextstep.security.builder.SecurityFilterOrder.OAUTH2_LOGIN_FILTER;
import static nextstep.security.builder.SecurityFilterOrder.OAUTH2_REDIRECT_FILTER;
import static nextstep.security.builder.SecurityFilterOrder.SECURITY_CONTEXT_FILTER;
import static nextstep.security.builder.SecurityFilterOrder.findOrder;
import static org.assertj.core.api.Assertions.assertThat;

class SecurityFilterOrderTest {

    @ParameterizedTest
    @DisplayName("기본 시큐리티 필터인지 확인한다")
    @MethodSource("기본_시큐리티_필터")
    void isSecurityFilter_test(Class<? extends Filter> filterClass) {
        boolean isSecurityFilter = SecurityFilterOrder.isSecurityFilter(filterClass);

        assertThat(isSecurityFilter).isTrue();
    }

    @Test
    @DisplayName("기본 시큐리티 필터가 아니면 false 를 반환한다")
    void isSecurityFilter_test_false() {
        boolean isSecurityFilter = SecurityFilterOrder.isSecurityFilter(NotSecurityFilter.class);

        assertThat(isSecurityFilter).isFalse();
    }


    @ParameterizedTest
    @DisplayName("기본 시큐리티 필터의 순서를 확인한다")
    @MethodSource("기본_시큐리티_필터")
    void findOrder_test(Class<? extends Filter> filterClass, SecurityFilterOrder securityFilterOrder) {
        Integer order = findOrder(filterClass);

        assertThat(order).isEqualTo(securityFilterOrder.getOrder());
    }


    @Test
    @DisplayName("기본 시큐리티 필터가 아니면 null을 반환한다")
    void findOrder_test_null() {
        Integer order = findOrder(NotSecurityFilter.class);

        assertThat(order).isNull();
    }

    private static Stream<Arguments> 기본_시큐리티_필터() {
        return Stream.of(
                Arguments.of(CsrfFilter.class, CSRF_FILTER),
                Arguments.of(SecurityContextHolderFilter.class, SECURITY_CONTEXT_FILTER),
                Arguments.of(UsernamePasswordAuthenticationFilter.class, FORM_LOGIN_FILTER),
                Arguments.of(BasicAuthenticationFilter.class, HTTP_BASIC_FILTER),
                Arguments.of(AuthorizationFilter.class, AUTHORIZATION_FILTER),
                Arguments.of(OAuth2AuthorizationRequestRedirectFilter.class, OAUTH2_REDIRECT_FILTER),
                Arguments.of(OAuth2LoginAuthenticationFilter.class, OAUTH2_LOGIN_FILTER)
        );
    }

    private static class NotSecurityFilter implements Filter {
        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        }
    }
}
