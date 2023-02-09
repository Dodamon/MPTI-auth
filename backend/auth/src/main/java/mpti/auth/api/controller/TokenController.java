package mpti.auth.api.controller;

import com.google.gson.Gson;
import lombok.RequiredArgsConstructor;
import mpti.auth.dao.UserRefreshTokenRepository;
import mpti.auth.dto.TokenDto;
import mpti.auth.entity.UserRefreshToken;
import mpti.common.security.TokenProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@CrossOrigin(origins = {"http://localhost:3000", "http://127.0.0.1:3000"})
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class TokenController {

    private final UserRefreshTokenRepository userRefreshTokenRepository;

    private final TokenProvider tokenProvider;

    private final Gson gson;
    @GetMapping("")
    public String checkDuplicateId() {
        return "<h1>Hello Auth Server Main Page</h1>";
    }

    /**
     * refresh 토큰이 DB에 있는 지 확인
     * @return
     */

//    @PostMapping("/token")
//    public ResponseEntity checkRefreshToken(@RequestBody String requestBody) {
//
//        TokenDto tokenDto = gson.fromJson(requestBody, TokenDto.class);
//        String refreshToken = tokenDto.getRefreshToken();
//
//        Optional<UserRefreshToken> byId = userRefreshTokenRepository.findById(refreshToken);
////        if()
////        System.out.println(byId.get().getUserEmail());
////        System.out.println(byId.get().getRefreshToken());
////        System.out.println(userRefreshTokenRepository.existsById(refreshToken));
////        tokenProvider.
//
////        Map<String, Boolean> resultResponse = new HashMap<>();
////        resultResponse.put("result" , userRefreshTokenRepository.existsById(refreshToken));
////        tokenDto.setState(userRefreshTokenRepository.existsById(refreshToken));
//
//        if(tokenDto.getState()) {
//
//            tokenDto.setAccessToken(tokenProvider.createAccessToken());
//        }
//
//        return ResponseEntity.ok(tokenDto);
//    }
}
