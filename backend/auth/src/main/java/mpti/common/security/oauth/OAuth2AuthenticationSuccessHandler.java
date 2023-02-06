package mpti.common.security.oauth;


import com.google.gson.Gson;
import lombok.RequiredArgsConstructor;
import mpti.auth.dao.UserRefreshTokenRepository;
import mpti.auth.entity.UserRefreshToken;
import mpti.common.exception.BadRequestException;
import mpti.common.security.TokenProvider;
import mpti.common.security.UserPrincipal;
import mpti.common.security.oauth.provider.OAuth2UserInfo;
import mpti.common.security.oauth.provider.OAuth2UserInfoFactory;
import mpti.auth.utils.CookieUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;

import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Optional;

import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.*;


@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    final private TokenProvider tokenProvider;

    final private HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;

    private final UserRefreshTokenRepository userRefreshTokenRepository;

    private static final Logger logger = LoggerFactory.getLogger(OAuth2AuthenticationSuccessHandler.class);

    private final Gson gson;

    @Value("${app.oauth2.authorizedRedirectUris}")
    private List<String> REDIRECT_URL;


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        if (response.isCommitted()) {
            logger.debug("이미 commit되어서 리다리렉트를 실행 할 수 없습니다 ");
            return;
        }

        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        logger.info(userPrincipal.getId() + "");

        if(userPrincipal.getNeedUpdate()) {
            // 소설로그인이 처음이라 추가 정보가 필요한 경우
            String targetUrl = makeTargetUrl(request, response, authentication);
            logger.info("[OAuth 로그인] 추가정보로 회원가입 필요 : " +  targetUrl);
            clearAuthenticationAttributes(request, response);
            getRedirectStrategy().sendRedirect(request, response, targetUrl);

        } else {
            // 소셜로그인으로 회원가입이 되어있는 경우
            String targetUrl = determineTargetUrl(request, response, authentication);
            logger.info("[OAuth 로그인] 로그인 최종성공 response 를 보냅니다 : " +  targetUrl);
            clearAuthenticationAttributes(request, response);
            getRedirectStrategy().sendRedirect(request, response, targetUrl);
        }

    }

    protected String makeTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        Optional<String> redirectUri = CookieUtils.getCookie(request, HttpCookieOAuth2AuthorizationRequestRepository.REDIRECT_URI_PARAM_COOKIE_NAME)
                .map(Cookie::getValue);
        if(redirectUri.isPresent() && !isAuthorizedRedirectUri(redirectUri.get())) {
            throw new BadRequestException(" We've got an Unauthorized Redirect URI and can't proceed with the authentication ");
        }
        String targetUrl = redirectUri.orElse(getDefaultTargetUrl());

        String accessToken = tokenProvider.createAccessToken(authentication);
        String refreshToken = tokenProvider.createRefreshToken(authentication);

        // redis DB에 refresh 토큰 저장
        UserRefreshToken userRefreshToken = UserRefreshToken
                .builder()
                .userEmail(authentication.getName())
                .refreshToken(refreshToken)
                .role(authentication.getAuthorities().iterator().next().toString())
                .build();

        userRefreshTokenRepository.save(userRefreshToken);
        logger.info("[OAuth 로그인] 새로 생성");

        return UriComponentsBuilder.fromUriString(targetUrl)
                .queryParam(ACCESS_TOKEN, accessToken)
                .queryParam(REFRESH_TOKEN, refreshToken)
                .queryParam("need_update", true)
                .queryParam("email", userPrincipal.getEmail())
                .queryParam("name", userPrincipal.getUsername())
                .build().toUriString();
    }


    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        // redirect url 검증 및 조회
        Optional<String> redirectUri = CookieUtils.getCookie(request, HttpCookieOAuth2AuthorizationRequestRepository.REDIRECT_URI_PARAM_COOKIE_NAME)
                .map(Cookie::getValue);
        if(redirectUri.isPresent() && !isAuthorizedRedirectUri(redirectUri.get())) {
            throw new BadRequestException(" We've got an Unauthorized Redirect URI and can't proceed with the authentication ");
        }
        String targetUrl = redirectUri.orElse(getDefaultTargetUrl());

        String accessToken = tokenProvider.createAccessToken(authentication);
        String refreshToken = tokenProvider.createRefreshToken(authentication);

        // redis DB에 refresh 토큰 저장
        UserRefreshToken userRefreshToken = UserRefreshToken
                .builder()
                .userEmail(authentication.getName())
                .refreshToken(refreshToken)
                .role(authentication.getAuthorities().iterator().next().toString())
                .build();

        userRefreshTokenRepository.save(userRefreshToken);
        logger.info("[OAuth 로그인] 새로 생성");

        return UriComponentsBuilder.fromUriString(targetUrl)
                .queryParam(ACCESS_TOKEN, accessToken)
                .queryParam(REFRESH_TOKEN, refreshToken)
                .queryParam("need_update", false)
                .build().toUriString();
    }

    protected void clearAuthenticationAttributes(HttpServletRequest request, HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);
        httpCookieOAuth2AuthorizationRequestRepository.removeAuthorizationRequestCookies(request, response);
    }

    private boolean isAuthorizedRedirectUri(String uri) {
        URI clientRedirectUri = URI.create(uri);

        return REDIRECT_URL.stream()
                .anyMatch(authorizedRedirectUri -> {
                    URI authorizedURI = URI.create(authorizedRedirectUri);
                    if(authorizedURI.getHost().equalsIgnoreCase(clientRedirectUri.getHost())
                            && authorizedURI.getPort() == clientRedirectUri.getPort()) {
                        return true;
                    }
                    return false;
                });
    }
}
