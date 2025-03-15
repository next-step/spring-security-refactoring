package nextstep.security.csrf;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import nextstep.security.access.RequestMatcher;
import nextstep.security.authorization.AccessDeniedException;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class CsrfFilter extends OncePerRequestFilter {
    private final CsrfTokenRepository csrfTokenRepository;
    private RequestMatcher requestMatcher;
    private final AccessDeniedHandler accessDeniedHandler;

    public CsrfFilter(final CsrfTokenRepository csrfTokenRepository) {
        this.csrfTokenRepository = csrfTokenRepository;
        this.accessDeniedHandler = new DefaultAccessDeniedHandler();
        this.requestMatcher = new DefaultCsrfRequestMatcher();
    }

    public void setRequestMatcher(final RequestMatcher requestMatcher) {
        this.requestMatcher = requestMatcher;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        var csrfToken = csrfTokenRepository.loadToken(request);
        boolean missingToken = csrfToken == null;
        if (missingToken) {
            csrfToken = csrfTokenRepository.generateToken(request);
            csrfTokenRepository.saveToken(csrfToken, request, response);
        }
        request.setAttribute(CsrfToken.class.getName(), csrfToken);

        if (!requestMatcher.matches(request)) {
            doFilter(request, response, filterChain);
            return;
        }

        var token = extractToken(request, csrfToken);
        if (!csrfToken.getToken().equals(token)) {
            AccessDeniedException exception = missingToken ? new MissingCsrfTokenException("토큰이 존재하지 않습니다.") : new InvalidCsrfTokenException("유효하지 않은 토큰입니다.");
            accessDeniedHandler.handle(request, response, exception);
            return;
        }

        filterChain.doFilter(request, response);
    }

    private String extractToken(final HttpServletRequest request, final CsrfToken csrfToken) {
        var actualToken = request.getHeader(csrfToken.getHeaderName());
        if (actualToken != null) {
            return actualToken;
        }
        return request.getParameter(csrfToken.getParameterName());
    }

}
