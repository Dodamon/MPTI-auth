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
import javax.transaction.Transactional;
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
        String targetUrl = determineTargetUrl(request, response, authentication);

        if (response.isCommitted()) {
            logger.debug("이미 commit되어서 리다리렉트를 실행 할 수 없습니다 " + targetUrl);
            return;
        }

        logger.info("[OAuth 로그인] 로그인 최종성공 response 를 보냅니다 : " +  targetUrl);
        clearAuthenticationAttributes(request, response);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    @Transactional
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        Optional<String> redirectUri = CookieUtils.getCookie(request, HttpCookieOAuth2AuthorizationRequestRepository.REDIRECT_URI_PARAM_COOKIE_NAME)
                .map(Cookie::getValue);

        if(redirectUri.isPresent() && !isAuthorizedRedirectUri(redirectUri.get())) {
            throw new BadRequestException("[OAuth 로그인] 권한이 없는 Redirect URL 입니다");
        }

        String targetUrl = redirectUri.orElse(getDefaultTargetUrl());

        // providerType으로 Authentication 객체에서 유저객체를 불러온다
        Object principal = authentication.getPrincipal();
        OAuth2AuthenticationToken authToken = (OAuth2AuthenticationToken) authentication;
        String providerType = authToken.getAuthorizedClientRegistrationId().toString();
        UserPrincipal userDetails = (UserPrincipal) principal;
        OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(providerType, userDetails.getAttributes());

        String accessToken = tokenProvider.createAccessToken(authentication);
        String refreshToken = tokenProvider.createRefreshToken(authentication);

        // DB에 저장
        // UserRefreshToken userRefreshToken = userRefreshTokenRepository.findByUserEmail(userInfo.getEmail());
//        UserRefreshToken userRefreshToken = userRefreshTokenRepository.findById();
//        if (userRefreshToken != null) {
//            userRefreshToken.setRefreshToken(refreshToken);
////            userRefreshTokenRepository.flush();
//            logger.info("[OAuth 로그인] 기존의 값 update");
//        } else {

//            List<GrantedAuthority> authorities = Collections.
//                    singletonList(new SimpleGrantedAuthority("ROLE_USER"));

            UserRefreshToken userRefreshToken = new UserRefreshToken(userInfo.getId(), refreshToken, authentication.getAuthorities());
//            userRefreshTokenRepository.saveAndFlush(userRefreshToken);
            userRefreshTokenRepository.save(userRefreshToken);
            logger.info("[OAuth 로그인] 새로 생성");
//        }

        //쿼리로 토큰을 보낸다
//        String json = gson.toJson(userInfo);
//
//
//        String data = "{\"response\":{\"error\":false,\"access_token\":\""+accessToken+"\", \"refresh_token\": \""+refreshToken+"\", \"role\": \""+"roleId"+"\"}}";
//        PrintWriter out = null;
//        try {

//            out = response.getWriter();
//        } catch (IOException e) {
//            throw new RuntimeException(e);
//        }
//        out.print(data);

        return UriComponentsBuilder.fromUriString(targetUrl)
                .queryParam(ACCESS_TOKEN, accessToken)
                .queryParam(REFRESH_TOKEN, refreshToken)
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
                    // Only validate host and port. Let the clients use different paths if they want to
                    URI authorizedURI = URI.create(authorizedRedirectUri);
                    if(authorizedURI.getHost().equalsIgnoreCase(clientRedirectUri.getHost())
                            && authorizedURI.getPort() == clientRedirectUri.getPort()) {
                        return true;
                    }
                    return false;
                });
    }
}
