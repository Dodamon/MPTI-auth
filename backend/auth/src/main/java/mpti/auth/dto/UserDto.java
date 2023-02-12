package mpti.auth.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;


import javax.validation.constraints.Email;
import javax.validation.constraints.NotNull;
import java.time.LocalDate;

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

    private String password;

    @NotNull
    private String provider;

    private String providerId;

    private Boolean needUpdate;

    private LocalDate stopUntil;

}
