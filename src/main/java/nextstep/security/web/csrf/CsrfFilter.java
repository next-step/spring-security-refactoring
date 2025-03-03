package nextstep.security.web.csrf;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import nextstep.security.access.MvcRequestMatcher;
import nextstep.security.access.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;
import java.util.Set;

public class CsrfFilter extends OncePerRequestFilter {
    private final RequestMatcher requireCsrfProtectionMatcher;
    private final AccessDeniedHandler accessDeniedHandler = new AccessDeniedHandler();
    private final CsrfTokenRepository tokenRepository;
    private final Set<MvcRequestMatcher> ignoringRequestMatchers;

    public CsrfFilter(RequestMatcher requireCsrfProtectionMatcher, Set<MvcRequestMatcher> ignoringRequestMatchers) {
        this.requireCsrfProtectionMatcher = requireCsrfProtectionMatcher;
        this.ignoringRequestMatchers = ignoringRequestMatchers;
        this.tokenRepository = new CsrfTokenRepository();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (ignoringRequestMatchers.stream().anyMatch(matcher -> matcher.matches(request))) {
            filterChain.doFilter(request, response);
            return;
        }

        CsrfToken csrfToken = this.tokenRepository.loadToken(request);

        boolean missingToken = (csrfToken == null);
        if (missingToken) {
            csrfToken = this.tokenRepository.generateToken(request);
            this.tokenRepository.saveToken(csrfToken, request, response);
        }

        request.setAttribute(CsrfToken.class.getName(), csrfToken);

        if (!this.requireCsrfProtectionMatcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        if (isNotValidToken(request, csrfToken)) {
            this.accessDeniedHandler.handle(request, response);
            return;
        }

        filterChain.doFilter(request, response);
    }

    private boolean isNotValidToken(HttpServletRequest request, CsrfToken csrfToken) {
        String actualToken = request.getHeader(csrfToken.getHeaderName());
        if (actualToken == null) {
            actualToken = request.getParameter(csrfToken.getParameterName());
        }

        return !Objects.equals(csrfToken.getToken(), actualToken);
    }
}
