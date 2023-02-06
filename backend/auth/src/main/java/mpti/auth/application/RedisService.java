package mpti.auth.application;

import lombok.RequiredArgsConstructor;
import mpti.auth.api.controller.AuthController;
import mpti.auth.dao.UserRefreshTokenRepository;
import mpti.auth.entity.UserRefreshToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RedisService {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    final private UserRefreshTokenRepository userRefreshTokenRepository;

    public void saveTokens(@AuthenticationPrincipal Authentication authentication, String refreshToken) {

        UserRefreshToken userRefreshToken = new UserRefreshToken(authentication.getName(), refreshToken, authentication.getAuthorities());
        userRefreshTokenRepository.save(userRefreshToken);

        logger.info("[Redis] save tokens in redis DB");

        if (!userRefreshTokenRepository.existsById(refreshToken)) {
            userRefreshToken = new UserRefreshToken(authentication.getName(), refreshToken, authentication.getAuthorities());
            logger.info("[일반로그인] 새로 생성한 토큰 " + userRefreshToken);
            userRefreshTokenRepository.save(userRefreshToken);
        } else {
            userRefreshToken.setRefreshToken(refreshToken);
            logger.info("[일반 로그인] 토큰을 기존의 값 update");
        }
        logger.info("[일반 로그인]" + refreshToken + "을 DB에 저장 성공");
    }
}
