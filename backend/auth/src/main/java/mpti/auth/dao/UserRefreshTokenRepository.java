package mpti.auth.dao;

import mpti.auth.entity.UserRefreshToken;
import org.springframework.data.repository.CrudRepository;

public interface UserRefreshTokenRepository extends CrudRepository<UserRefreshToken, String> {

}
