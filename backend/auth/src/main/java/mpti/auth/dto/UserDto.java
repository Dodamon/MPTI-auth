package mpti.auth.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;


import javax.validation.constraints.Email;
import javax.validation.constraints.NotNull;

@Builder
@Getter
@Setter
public class UserDto {

    private Long id;

    @NotNull
    private String name;

    @Email
    @NotNull
    private String email;

    private String imageUrl;

    private Boolean emailVerified = false;

    private String password;

    @NotNull
    private String provider;

    private String providerId;

    private Boolean needUpdate;


//    public Long getId() {
//        return id;
//    }
//
//    public void setId(Long id) {
//        this.id = id;
//    }
//
//    public String getName() {
//        return name;
//    }
//
//    public void setName(String name) {
//        this.name = name;
//    }
//
//    public String getEmail() {
//        return email;
//    }
//
//    public void setEmail(String email) {
//        this.email = email;
//    }
//
//    public String getImageUrl() {
//        return imageUrl;
//    }
//
//    public void setImageUrl(String imageUrl) {
//        this.imageUrl = imageUrl;
//    }
//
//    public Boolean getEmailVerified() {
//        return emailVerified;
//    }
//
//    public void setEmailVerified(Boolean emailVerified) {
//        this.emailVerified = emailVerified;
//    }
//
//    public String getPassword() {
//        return password;
//    }
//
//    public void setPassword(String password) {
//        this.password = password;
//    }
//
//    public AuthProvider getProvider() {
//        return provider;
//    }
//
//    public void setProvider(AuthProvider provider) {
//        this.provider = provider;
//    }
//
//    public String getProviderId() {
//        return providerId;
//    }
//
//    public void setProviderId(String providerId) {
//        this.providerId = providerId;
//    }
}
