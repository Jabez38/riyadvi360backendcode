package registerandlogin;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.web.bind.annotation.GetMapping;


@SpringBootApplication
@EnableScheduling
public class RegisterLoginApplication {
	  @GetMapping("/jab")  
	    public String hello()   
	    {  
	    return "Hello User, have a nice day.";  
	    }  
	public static void main(String[] args) {
		SpringApplication.run(RegisterLoginApplication.class, args);
		
	
		    
	}

	}
