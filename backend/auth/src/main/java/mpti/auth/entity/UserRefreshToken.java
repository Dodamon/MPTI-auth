package mpti.auth.entity;

import lombok.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.annotation.*;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.security.core.GrantedAuthority;


import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.util.Collection;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@RedisHash(timeToLive = 604800 ) //Sec -> 7일
public class UserRefreshToken {
    @NotNull
    @Size(max = 256)
    @Id
    private String refreshToken;

    @NotNull
    private String userEmail;

    @NotNull
    private String role;

    public UserRefreshToken(String name, String refreshToken, Collection<? extends GrantedAuthority> authorities) {

        this.refreshToken = refreshToken;
        this.userEmail = name;
        this.role = authorities.iterator().next().toString();
    }
}
