package nextstep.security.csrf;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import nextstep.security.authorization.AccessDeniedException;
import org.springframework.http.HttpMethod;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class CsrfFilter extends OncePerRequestFilter {

    private final CsrfTokenRepository csrfTokenRepository = new CsrfTokenRepository();
    private final AccessDeniedHandler accessDeniedHandler = new AccessDeniedHandler();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        CsrfToken actualToken = csrfTokenRepository.loadToken(request);
        if (actualToken == null) {
            actualToken = csrfTokenRepository.generateToken(request);
            csrfTokenRepository.saveToken(actualToken, request, response);
        }

        request.setAttribute(actualToken.parameterName(), actualToken);
        request.setAttribute(actualToken.headerName(), actualToken);

        if (!HttpMethod.POST.name().equalsIgnoreCase(request.getMethod())) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            validateToken(request, actualToken);
        } catch (AccessDeniedException e) {
            accessDeniedHandler.onAccessFailure(response, e);
        }

        filterChain.doFilter(request, response);
    }

    public void validateToken(HttpServletRequest request, CsrfToken actualToken) {
        String headerToken = request.getHeader(actualToken.headerName());
        String paramToken = request.getParameter(actualToken.parameterName());

        boolean validToken = (headerToken != null && headerToken.equals(actualToken.token())) ||
                (paramToken != null && paramToken.equals(actualToken.token()));

        if (!validToken) {
            throw new AccessDeniedException("CSRF token validation failed");
        }
    }
}
