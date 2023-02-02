package mpti.auth.api.response;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthResponse {
    private String accessExpiryDate;
    private String refreshExpiryDate;

    public AuthResponse(String accessExpiryDate, String refreshExpiryDate) {
        this.accessExpiryDate = accessExpiryDate;
        this.refreshExpiryDate = refreshExpiryDate;
    }

    public AuthResponse(String accessExpiryDate) {
        this.accessExpiryDate = accessExpiryDate;
    }
}
