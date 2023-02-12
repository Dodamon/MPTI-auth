package mpti.auth.application;

import com.google.gson.*;
import lombok.RequiredArgsConstructor;
import mpti.auth.api.request.LoginRequest;
import mpti.auth.dto.UserDto;
import okhttp3.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;


import java.io.IOException;
import java.lang.reflect.Type;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

@Service
@RequiredArgsConstructor
public class AuthService {
    private OkHttpClient client = new OkHttpClient();
    private final String USER = "ROLE_USER";
    private final String TRAINER = "ROLE_TRAINER";

    @Value("${app.auth.trainerServerUrl}")
    private String TRAINER_SERVER_URL;
    @Value("${app.auth.userServerUrl}")
    private String USER_SERVER_URL;

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    Gson gson = new GsonBuilder().registerTypeAdapter(LocalDate.class, new JsonSerializer<LocalDate>() {
        @Override
        public JsonElement serialize(LocalDate src, Type typeOfSrc, JsonSerializationContext context) {
            return new JsonPrimitive(src.format(DateTimeFormatter.ISO_LOCAL_DATE));
        }

    }).registerTypeAdapter(LocalDate.class,  new JsonDeserializer<LocalDate>(){
        @Override
        public LocalDate deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context)
                throws JsonParseException {
            return LocalDate.parse(json.getAsString(),
                    DateTimeFormatter.ofPattern("yyyy-MM-dd"));
        }

    }).create();

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

    public UserDto getUserByEmail(String email) {return makeUserRequest(email, USER_SERVER_URL);}
    public UserDto getTrainerByEmail(String email) {
        return makeUserRequest(email, TRAINER_SERVER_URL);
    }
}
