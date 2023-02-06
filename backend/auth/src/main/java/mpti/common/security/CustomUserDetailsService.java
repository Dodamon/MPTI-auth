package mpti.common.security;

import com.google.gson.Gson;
import lombok.RequiredArgsConstructor;
import mpti.auth.api.request.LoginRequest;
import mpti.auth.application.AuthService;
import okhttp3.*;

import mpti.auth.dto.UserDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.io.IOException;


@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private static final Logger logger = LoggerFactory.getLogger(CustomUserDetailsService.class);

    public static final MediaType JSON = MediaType.get("application/json; charset=utf-8");

    private OkHttpClient client = new OkHttpClient();

    private final Gson gson;

    private final String USER = "ROLE_USER";
    private final String TRAINER = "ROLE_TRAINER";

    @Value("${app.auth.trainerServerUrl}")
    private String TRAINER_SERVER_URL;
    @Value("${app.auth.userServerUrl}")
    private String USER_SERVER_URL;

    private final AuthService authService;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

        // 회원이 DB에 있는 지 확인
        UserDto user = authService.getUserByEmail(email);
        user.setNeedUpdate(false);

        if (user == null) {
            throw new UsernameNotFoundException(email + "not found");
        }

        logger.info(user.toString());
        return UserPrincipal.create(user, USER);

    }

}