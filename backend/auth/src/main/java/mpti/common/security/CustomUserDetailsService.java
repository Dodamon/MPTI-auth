package mpti.common.security;

import com.google.gson.Gson;
import lombok.RequiredArgsConstructor;
import mpti.auth.api.request.LoginRequest;
import mpti.auth.application.AuthService;
import mpti.common.errors.UserNotFoundException;
import okhttp3.*;

import mpti.auth.dto.UserDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletResponse;
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

    private final String ADMIN = "ROLE_ADMIN";

    private final String ADMIN_EMAIL = "admin123@admin.com";

    @Value("${app.auth.trainerServerUrl}")
    private String TRAINER_SERVER_URL;
    @Value("${app.auth.userServerUrl}")
    private String USER_SERVER_URL;

    private final AuthService authService;

    @Override
    public UserDetails loadUserByUsername(String email) {

        if(email.equals(ADMIN_EMAIL)) {
            UserDto admin = UserDto.builder()
                    .id(12345L)
                    .name("ADMIN")
                    .email(ADMIN_EMAIL)
                    .password("$2a$12$pg1UC8hREv8ijEPGG1UAn.w1SZ3aFjd..P.LIBWT.wZko.jsPQiYW")
                    .needUpdate(false)
                    .build();

            return UserPrincipal.create(admin, ADMIN);
        }

        // 회원이 User 와 Trainer DB에 있는 지 확인
        UserDto user = authService.getUserByEmail(email);
        String role = USER;
        if(user == null) {
            user = authService.getTrainerByEmail(email);
            role = TRAINER;
        }
        logger.info("DB확인 완료");

        if (user == null) {
            logger.error(email + "not found");
            throw new UserNotFoundException(email + "not found");
        }

        user.setNeedUpdate(false);
        logger.info(user.toString());
        return UserPrincipal.create(user, role);

    }

}