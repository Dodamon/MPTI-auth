package mpti.common.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.security.Key;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class TokenProvider implements InitializingBean {
    private static final Logger logger = LoggerFactory.getLogger(TokenProvider.class);

    private static final String AUTHORITIES_KEY = "auth";
    @Value("${app.auth.tokenSecret:}")
    private String SECRET_KEY;
    @Value("${app.auth.accessTokenExpirationMsec}")
    private long ACCESS_TOKEN_EXPIRATION;
    @Value("${app.auth.refreshTokenExpirationMsec}")
    private long REFRESH_TOKEN_EXPIRATION;

    private Key key;


    @Override
    public void afterPropertiesSet() throws Exception {
        // 주입받은 secret 값을 key로 할당 받기 위해서
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    public String createAccessToken(Authentication authentication) {

        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + ACCESS_TOKEN_EXPIRATION);


        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, SECRET_KEY)
                .compact();
    }

    public String renewAccessToken(String name, String role) {

        List<GrantedAuthority> authorities = Collections.
                singletonList(new SimpleGrantedAuthority(role));

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + ACCESS_TOKEN_EXPIRATION);

        return Jwts.builder()
                .setSubject(name)
                .claim(AUTHORITIES_KEY, authorities)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, SECRET_KEY)
                .compact();
    }

    public String createRefreshToken(Authentication authentication) {

        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        logger.info("authorities :: " + authorities);

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + REFRESH_TOKEN_EXPIRATION);


        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, SECRET_KEY)
                .compact();
    }

    public String getJwtRefreshFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Refresh-token");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7, bearerToken.length());
        }
        return null;
    }

    public boolean validateToken(String authToken) {
        logger.info("토큰 겁사필터 시작");
        try {
            Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(authToken);
            logger.info("유효한 jwt access tocken 입니다");
            return true;
        } catch (SignatureException ex) {
            logger.error("유효하지 않은 jwt access tocken 서명입니다"); //"Invalid JWT signature"
        } catch (MalformedJwtException ex) {
            logger.error("유효하지 않은 jwt access tocken 입니다"); // Invalid JWT token
        } catch (ExpiredJwtException ex) {
            logger.error("만료된 jwt access tocken 입니다"); // Expired JWT token
        } catch (UnsupportedJwtException ex) {
            logger.error("지원하지 않는 형식의 jwt access tocken 입니다"); // Unsupported JWT token
        } catch (IllegalArgumentException ex) {
            logger.error("jwt access tocken의 claims이 비어 있습니다"); // JWT claims string is empty.
        }
        return false;
    }

    public Claims getExpiredTokenClaims(String authToken) {
        try {
            Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(authToken);
        } catch (ExpiredJwtException e) {
            logger.info("만료된 jwt access tocken 입니다[1]"); // "Expired JWT token."
            return e.getClaims();
        }
        return null;
    }

    public String getUserEmailFromToken(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(SECRET_KEY)
                .parseClaimsJws(token)
                .getBody();

        return claims.getSubject();
    }

}