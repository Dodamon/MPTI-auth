package mpti.common.security.oauth;


import com.google.gson.Gson;
import lombok.RequiredArgsConstructor;
import mpti.auth.api.request.LoginRequest;
import mpti.auth.api.request.SocialSignUpRequest;
import mpti.auth.dto.AuthProvider;
import mpti.auth.dto.User;
import mpti.common.exception.OAuth2AuthenticationProcessingException;
import mpti.common.exception.ResourceNotFoundException;
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

        User user = processTrainerOAuth2User(oAuth2UserRequest,oAuth2UserInfo);
        if(user != null) return UserPrincipal.create(user, oAuth2User.getAttributes());

        user = processMemberOAuth2User(oAuth2UserRequest, oAuth2UserInfo);
        if(user != null) return UserPrincipal.create(user, oAuth2User.getAttributes());

        user = registerNewUser(oAuth2UserRequest, oAuth2UserInfo);
        logger.info(user.getProvider() + "[OAuth 로그인] 소셜 로그인을 처음 시도해서 데이터 DB에 저장성공");
        return UserPrincipal.create(user, oAuth2User.getAttributes());

    }



    private User processTrainerOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2UserInfo oAuth2UserInfo) {
        // oAuth2UserRequest 데이터에 대한 후처리 되는 함수
        // 함수 종료시 @AuthenticationPrincipal 어노테이션이 생성
        logger.info("[OAuth 로그인]트레이너 DB 조회");
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail(oAuth2UserInfo.getEmail());
        String json = gson.toJson(loginRequest);

        RequestBody requestBody = RequestBody.create(MediaType.get("application/json; charset=utf-8"), json);
        Request request = new Request.Builder()
//                .url("http://localhost:8002/api/auth/login")
                .url(TRAINER_SERVER_URL + "/login")
                .post(requestBody)
                .build();

        User user = null;
        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()){
                logger.error("응답에 실패했습니다 == 로그인을 할 수 없습니다");
            }else{
                String st = response.body().string();
                user = gson.fromJson(st, User.class);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        if(user != null) {
            if(!user.getProvider().equals(AuthProvider.valueOf(oAuth2UserRequest.getClientRegistration().getRegistrationId()))) {
                throw new OAuth2AuthenticationProcessingException("다른 방식으로 로그인을 시도해주세요");
            }
            logger.info(user.getProvider() + "[OAuth 로그인] 소셜 로그인을 이미 한적이 있습니다");
            user = updateExistingUser(user, oAuth2UserInfo);
        }

        return user;
//        return UserPrincipal.create(user, oAuth2User.getAttributes());
    }

    private User processMemberOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2UserInfo oAuth2UserInfo) {

        logger.info("[OAuth 로그인] 유저 DB 조회");
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail(oAuth2UserInfo.getEmail());
        String json = gson.toJson(loginRequest);

        RequestBody requestBody = RequestBody.create(MediaType.get("application/json; charset=utf-8"), json);
        Request request = new Request.Builder()
//                .url("http://localhost:8002/api/auth/login")
                .url(USER_SERVER_URL + "/login")
                .post(requestBody)
                .build();

        User user = null;
        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()){
                logger.error("응답에 실패했습니다 == 로그인을 할 수 없습니다");
            }else{
                String st = response.body().string();
                user = gson.fromJson(st, User.class);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        if(user != null) {
            if(!user.getProvider().equals(AuthProvider.valueOf(oAuth2UserRequest.getClientRegistration().getRegistrationId()))) {
                throw new OAuth2AuthenticationProcessingException("다른 방식으로 로그인을 시도해주세요");
            }
            logger.info(user.getProvider() + "[OAuth 로그인] 소셜 로그인을 이미 한적이 있습니다");
            user = updateExistingUser(user, oAuth2UserInfo);
        }

        return user;
    }

    private User updateExistingUser(User existingUser, OAuth2UserInfo oAuth2UserInfo) {

        Map<String, Object> updateRequest = new HashMap<>();
        updateRequest.put("email", existingUser.getEmail());

        String json = gson.toJson(updateRequest);
        logger.info(json);
        RequestBody requestBody = RequestBody.create(MediaType.get("application/json; charset=utf-8"), json);
        Request request = new Request.Builder()
                .url(USER_SERVER_URL +"/update")
                .post(requestBody)
                .build();

        User user = new User();
        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()){
                logger.error("응답에 실패했습니다");
            }else{
                String st = response.body().string();
                user = gson.fromJson(st, User.class);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        if(user == null) {
            throw new ResourceNotFoundException("[OAuth] 회원가입 실패", "", "");
        }
        return user;

        //existingUser.setImageUrl(oAuth2UserInfo.getImageUrl());
        //return userRepository.save(existingUser);
    }


    private User registerNewUser(OAuth2UserRequest oAuth2UserRequest, OAuth2UserInfo oAuth2UserInfo) {
//        User user = new User();
//        user.setProvider(AuthProvider.valueOf(oAuth2UserRequest.getClientRegistration().getRegistrationId()));
//        user.setProviderId(oAuth2UserInfo.getId());
//        user.setName(oAuth2UserInfo.getName());
//        user.setEmail(oAuth2UserInfo.getEmail());
//        user.setImageUrl(oAuth2UserInfo.getImageUrl());

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
        logger.info(json);
        RequestBody requestBody = RequestBody.create(MediaType.get("application/json; charset=utf-8"), json);
        Request request = new Request.Builder()
                .url(USER_SERVER_URL+"/signup")
                .post(requestBody)
                .build();

        User user = new User();
        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()){
                logger.error("응답에 실패했습니다");
            }else{
                String st = response.body().string();
                user = gson.fromJson(st, User.class);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        if(user == null) {
            throw new ResourceNotFoundException("[OAuth] 회원가입 실패", "", "");
        }
        return user;
    }
}
