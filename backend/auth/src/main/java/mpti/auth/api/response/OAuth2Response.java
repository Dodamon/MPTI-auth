package mpti.auth.api.response;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class OAuth2Response {
    private String accessExpiryDate;
    private String refreshExpiryDate;
    private String access_token;
    private String refresh_token;
}
