package mpti.common.security;

import lombok.RequiredArgsConstructor;
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

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private static final Logger logger = LoggerFactory.getLogger(CustomUserDetailsService.class);

    public static final MediaType JSON = MediaType.get("application/json; charset=utf-8");

    private OkHttpClient client = new OkHttpClient();

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
        UserDto user = authService.getTrainerByEmail(email);
        String role = TRAINER;
        if(user == null) {
            user = authService.getUserByEmail(email);
            role = USER;
        }

        if (user == null) {
            logger.error(email + " not found");
            throw new UsernameNotFoundException(email + " not found");
        }

        user.setNeedUpdate(false);
        return UserPrincipal.create(user, role);
    }

}