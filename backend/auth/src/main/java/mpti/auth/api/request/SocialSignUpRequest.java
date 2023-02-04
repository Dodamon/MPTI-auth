package mpti.auth.api.request;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;

/**
 * 최초 소셜로그인시 회원가입 될때 사용 -> 추가 정보 필요?!
 */
@Builder
@Getter
@Setter
public class SocialSignUpRequest {
    @NotBlank
    private String name;
    @NotBlank
    @Email
    private String email;
    @NotBlank
    private String password;
    private String provider;






}
