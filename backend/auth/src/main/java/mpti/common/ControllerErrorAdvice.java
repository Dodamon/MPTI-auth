package mpti.common;

import mpti.common.ErrorResponse;
import mpti.common.errors.*;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ControllerErrorAdvice {

    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    @ExceptionHandler(BadCredentialsException.class)
    public ErrorResponse handleBadCredentialsException() {
        return new ErrorResponse("아이디 또는 비밀번호가 맞지 않습니다. 다시 확인해 주세요.");
    }

    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    @ExceptionHandler(InternalAuthenticationServiceException.class)
    public ErrorResponse handleInternalAuthenticationServiceException() {
        return new ErrorResponse("내부적으로 발생한 시스템 문제로 인해 요청을 처리할 수 없습니다. 관리자에게 문의하세요.");
    }

    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    @ExceptionHandler(UsernameNotFoundException.class)
    public ErrorResponse handleUsernameNotFoundException() {
        return new ErrorResponse("계정이 존재하지 않습니다. 회원가입 진행 후 로그인 해주세요.");
    }

//    @ResponseStatus(HttpStatus.UNAUTHORIZED)
//    @ExceptionHandler(UserNotFoundException.class)
//    public ErrorResponse handleUserNotFoundException() {
//        return new ErrorResponse("계정이 존재하지 않습니다. 회원가입 진행 후 로그인 해주세요.");
//    }

    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    @ExceptionHandler(AuthenticationCredentialsNotFoundException.class)
    public ErrorResponse handleAuthenticationCredentialsNotFoundException() {
        return new ErrorResponse("인증 요청이 거부되었습니다. 관리자에게 문의하세요.");
    }

    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    @ExceptionHandler(StopUntilException.class)
    public ErrorResponse handleStopUntilExceptionException(Exception e) {
        return new ErrorResponse("정지된 회원입니다 : " + e.getMessage());
    }

}
