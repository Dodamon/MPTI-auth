package mpti.common.errors;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class StopUntilException extends RuntimeException {
    public  StopUntilException(String message) {
        super(message);
    }

    public  StopUntilException(String message, Throwable cause) {
        super(message, cause);
    }
}
