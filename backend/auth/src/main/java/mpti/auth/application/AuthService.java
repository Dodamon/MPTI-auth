package mpti.auth.application;

import com.google.gson.Gson;
import lombok.RequiredArgsConstructor;
import mpti.auth.api.request.LoginRequest;
import mpti.auth.dto.UserDto;
import mpti.common.exception.ResourceNotFoundException;
import mpti.common.security.UserPrincipal;
import okhttp3.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;


import java.io.IOException;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final Gson gson;
    private OkHttpClient client = new OkHttpClient();
    private final String USER = "ROLE_USER";
    private final String TRAINER = "ROLE_TRAINER";

    @Value("${app.auth.trainerServerUrl}")
    private String TRAINER_SERVER_URL;
    @Value("${app.auth.userServerUrl}")
    private String USER_SERVER_URL;

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    public UserDto makeUserRequest(String email, String targetUrl) {
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail(email);
        String json = gson.toJson(loginRequest);

        RequestBody requestBody = RequestBody.create(MediaType.get("application/json; charset=utf-8"), json);
        Request request = new Request.Builder()
                .url(targetUrl + "/login")
                .post(requestBody)
                .build();

        UserDto userDto = null;
        try (Response response = client.newCall(request).execute()) {
            if (response.isSuccessful()){
                String st = response.body().string();
                userDto = gson.fromJson(st, UserDto.class);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return userDto;
    }

    public UserDto getUserByEmail(String email) {
        UserDto userDto = makeUserRequest(email, TRAINER_SERVER_URL);

        if(userDto == null) userDto = makeUserRequest(email, USER_SERVER_URL);
        return userDto;
    }
}
