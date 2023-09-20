package registerandlogin;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.web.bind.annotation.GetMapping;

import com.twilio.Twilio;
import com.twilio.exception.ApiException;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;

@SpringBootApplication
@EnableScheduling
public class RegisterLoginApplication {
	
	
	
	   
	public static void main(String[] args) {
		SpringApplication.run(RegisterLoginApplication.class, args);
		

		    
	}
	
		    
	}

	
