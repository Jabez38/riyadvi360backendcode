package registerandlogin.user;

import java.util.List;

import javax.validation.Valid;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

	User findByEmail(String email);

	Contactuser save(@Valid Contactuser contact);


//	User findByEmail();

//	String findByPassword(String email);

//	void save(@Valid Contactuser newUser);

//	User findByUsername();

//	User findByEmail(String email);

	
}
