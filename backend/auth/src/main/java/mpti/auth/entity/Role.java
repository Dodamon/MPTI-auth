package mpti.auth.entity;

import org.springframework.security.core.GrantedAuthority;

public enum Role implements GrantedAuthority {
    MEMBER("ROLE_MEMBER"),
    TRAINER("ROLE_TRAINER"),
    ADMIN("ROLE_ADMIN");
    private String authority;

    Role(String authority) {
        this.authority = authority;
    }

    @Override
    public String getAuthority() {
        return authority;
    }
}