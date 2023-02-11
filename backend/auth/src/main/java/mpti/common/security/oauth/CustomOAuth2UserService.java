package mpti.common.security.oauth;


import com.google.gson.Gson;
import lombok.RequiredArgsConstructor;
import mpti.auth.api.request.SocialSignUpRequest;
import mpti.auth.application.AuthService;
import mpti.auth.dto.AuthProvider;
import mpti.auth.dto.UserDto;
import mpti.common.errors.OAuth2AuthenticationProcessingException;
import mpti.common.errors.ResourceNotFoundException;
import mpti.common.security.UserPrincipal;
import mpti.common.security.oauth.provider.OAuth2UserInfo;
import mpti.common.security.oauth.provider.OAuth2UserInfoFactory;
import okhttp3.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private static final Logger logger = LoggerFactory.getLogger(CustomOAuth2UserService.class);

    public static final MediaType JSON = MediaType.get("application/json; charset=utf-8");

    private OkHttpClient client = new OkHttpClient();

    private final Gson gson;
    private final AuthService authService;

    @Value("${app.auth.tokenSecret:}")
    private String SECRET_KEY;
    @Value("${app.auth.accessTokenExpirationMsec}")
    private long ACCESS_TOKEN_EXPIRATION;
    @Value("${app.auth.refreshTokenExpirationMsec}")
    private long REFRESH_TOKEN_EXPIRATION;
    @Value("${app.auth.userServerUrl}")
    private String USER_SERVER_URL;
    @Value("${app.auth.trainerServerUrl}")
    private String TRAINER_SERVER_URL;


    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {
        // oAuth2UserRequest는 OAuth 로그인 성공시 accessToken을 통해 응답 받은 객체

        OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);
        logger.info(oAuth2User.getAttributes().toString());

        try {
            return processOAuth2User(oAuth2UserRequest, oAuth2User);
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }


    private OAuth2User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {

        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(oAuth2UserRequest.getClientRegistration().getRegistrationId(), oAuth2User.getAttributes());
        if(StringUtils.isEmpty(oAuth2UserInfo.getEmail())) {
            throw new OAuth2AuthenticationProcessingException("Email not found from OAuth2 provider");
        }

        UserDto user = authService.getUserByEmail(oAuth2UserInfo.getEmail());

        if(user != null) {
            logger.info(AuthProvider.valueOf(oAuth2UserRequest.getClientRegistration().getRegistrationId()) + "");
            logger.info(user.getProvider());

            // 회원가입을 했던 회왼 -> 바로 user 조회
            user = updateExistingUser(user, oAuth2UserInfo);
            user.setNeedUpdate(false);
        } else {
            // 회원가입이 처음인 회원 -> 추가 정보 요청 send Redirect
             user = registerNewUser(oAuth2UserRequest, oAuth2UserInfo);
             user.setNeedUpdate(true);
        }
        return UserPrincipal.create(user, oAuth2User.getAttributes());

    }



    private UserDto updateExistingUser(UserDto existingUser, OAuth2UserInfo oAuth2UserInfo) {

        Map<String, Object> updateRequest = new HashMap<>();
        updateRequest.put("email", existingUser.getEmail());

        String json = gson.toJson(updateRequest);
        RequestBody requestBody = RequestBody.create(MediaType.get("application/json; charset=utf-8"), json);
        Request request = new Request.Builder()
                .url(USER_SERVER_URL +"/update")
                .post(requestBody)
                .build();

        UserDto user = null;
        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()){
                logger.error("응답에 실패했습니다");
            }else{
                String st = response.body().string();
                user = gson.fromJson(st, UserDto.class);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        if(user == null) {
            throw new ResourceNotFoundException("User", "email", existingUser.getEmail());
        }
        return user;
    }


    private UserDto registerNewUser(OAuth2UserRequest oAuth2UserRequest, OAuth2UserInfo oAuth2UserInfo) {

        // 회원만 소셜로그인으로 회원가입이 가능하다
        logger.info("[OAuth 로그인] 회원 회원가입");
        logger.info(oAuth2UserInfo.toString());


        SocialSignUpRequest socialSignUpRequest = SocialSignUpRequest.builder()
                .name(oAuth2UserInfo.getName())
                .password(oAuth2UserInfo.getId())
                .email(oAuth2UserInfo.getEmail())
                .provider(oAuth2UserInfo.getProvider())
                .build();

        String json = gson.toJson(socialSignUpRequest);
        RequestBody requestBody = RequestBody.create(MediaType.get("application/json; charset=utf-8"), json);
        Request request = new Request.Builder()
                .url(USER_SERVER_URL+"/signup")
                .post(requestBody)
                .build();

        UserDto user = null;
        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()){
                logger.error("응답에 실패했습니다");
            }else{
                String st = response.body().string();
                user = gson.fromJson(st, UserDto.class);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        if(user == null) {
            throw new ResourceNotFoundException("User", "email", oAuth2UserInfo.getName());
        }
        return user;
    }
}
