package mpti.common.security;

import mpti.auth.dto.UserDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class UserPrincipal implements OAuth2User, UserDetails {
    private Long id;
    private String email;
    private String name;
    private String password;
    private boolean needUpdate;
    private Collection<? extends GrantedAuthority> authorities;
    private Map<String, Object> attributes;

    private static final Logger logger = LoggerFactory.getLogger(UserPrincipal.class);

    private UserPrincipal(Long id, String name, String email, String password, Boolean needUpdate, Collection<? extends GrantedAuthority> authorities) {
        this.id = id;
        this.name = name;
        this.email = email;
        this.password = password;
        this.needUpdate = needUpdate;
        this.authorities = authorities;
    }

    public static UserPrincipal create(UserDto user, String role) { // ROLE_TRAINER, ROLE_USER
        List<GrantedAuthority> authorities = Collections.
                singletonList(new SimpleGrantedAuthority(role));

        logger.info(user.getId() + "");
        logger.info(user.getName());
        logger.info(user.getEmail());
        logger.info(user.getPassword());
        logger.info(user.getNeedUpdate() + "");

        UserPrincipal userPrincipal = new UserPrincipal(
                user.getId(),
                user.getName(),
                user.getEmail(),
                user.getPassword(),
                user.getNeedUpdate(),
                authorities
        );

        return new UserPrincipal(
                user.getId(),
                user.getName(),
                user.getEmail(),
                user.getPassword(),
                user.getNeedUpdate(),
                authorities
        );
    }
    // OAuth로그인 시는 무조건 USER권한
    public static UserPrincipal create(UserDto user, Map<String, Object> attributes) {
        UserPrincipal principalDetails = UserPrincipal.create(user, "ROLE_USER");
        principalDetails.setAttributes(attributes);
        return principalDetails;
    }

    public Long getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public Boolean getNeedUpdate(){ return  needUpdate; }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    public void setAttributes(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getName() {
        return String.valueOf(id);
    }
}
