package com.cruddemo.security.oauth;

import com.cruddemo.config.AppProperties;
import com.cruddemo.security.JWTTokenProvider;
import com.cruddemo.security.oauth.common.HttpCookieOAuth2AuthorizationRequestRepository;
import com.cruddemo.utils.AppWebUtils;
import com.cruddemo.utils.exceptions.BadRequestException;
import com.fasterxml.jackson.core.JsonProcessingException;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;

import static com.cruddemo.security.oauth.common.OAuth2Util.ORIGINAL_REQUEST_URI_PARAM_COOKIE_NAME;
import static com.cruddemo.security.oauth.common.OAuth2Util.REDIRECT_URI_PARAM_COOKIE_NAME;

@Service
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    @Autowired
    private JWTTokenProvider jwtTokenProvider;

    @Autowired
    private HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;

    @Autowired
    private AppProperties appProperties;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        String targetUrl = determineTargetUrl(request, response, authentication);

        if (response.isCommitted()) {
            logger.debug("Response has already been committed. Unable to redirect to " + targetUrl);
            return;
        }

        clearAuthenticationAttributes(request, response);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    protected String determineTargetUrl(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) {
        Optional<String> redirectUri = AppWebUtils.getCookie(request, REDIRECT_URI_PARAM_COOKIE_NAME)
                .map(Cookie::getValue);
        Optional<String> originalRequestUri = AppWebUtils.getCookie(request, ORIGINAL_REQUEST_URI_PARAM_COOKIE_NAME)
                .map(Cookie::getValue);

        if (redirectUri.isPresent() && !isRedirectOriginAuthorized(redirectUri.get())) {
            throw new BadRequestException("Sorry! We've got an Unauthorized Redirect URI and can't proceed with the authentication");
        }

        String targetUrl = redirectUri.orElse(getDefaultTargetUrl());

        String token = null;
        try {
            token = jwtTokenProvider.generateToken(authentication).toString();
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }

        return UriComponentsBuilder.fromUriString(targetUrl)
                .queryParam("token", URLEncoder.encode(token, StandardCharsets.UTF_8))
//                .queryParam("token", token)
                .queryParam(ORIGINAL_REQUEST_URI_PARAM_COOKIE_NAME, originalRequestUri)
                .build().toUriString();
    }

    protected void clearAuthenticationAttributes(HttpServletRequest request,
                                                 HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);
        httpCookieOAuth2AuthorizationRequestRepository.removeAuthorizationRequestCookies(request, response);
    }

    private boolean isRedirectOriginAuthorized(String uri) {
        URI clientRedirectUri = URI.create(uri);

        return Arrays.stream(appProperties.getOAuth2().getAuthorizedRedirectOrigins())
                .anyMatch(authorizedRedirectOrigin -> {
                    URI authorizedURI = URI.create(authorizedRedirectOrigin);
                    if (authorizedURI.getHost().equalsIgnoreCase(clientRedirectUri.getHost())
                            && authorizedURI.getPort() == clientRedirectUri.getPort()) {
                        return true;
                    }
                    return false;
                });
    }


}
