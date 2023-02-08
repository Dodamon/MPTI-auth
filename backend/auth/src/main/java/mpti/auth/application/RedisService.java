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

        if (!userRefreshTokenRepository.existsById(refreshToken)) {
            userRefreshToken = new UserRefreshToken(authentication.getName(), refreshToken, authentication.getAuthorities());
            userRefreshTokenRepository.save(userRefreshToken);
        } else {
            userRefreshToken.setRefreshToken(refreshToken);
        }

        logger.info("[Redis] save tokens in redis DB");
        logger.info(refreshToken);
    }
}
