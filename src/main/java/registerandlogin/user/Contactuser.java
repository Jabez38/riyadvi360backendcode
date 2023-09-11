package registerandlogin.user;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.validation.constraints.NotBlank;

@Entity
@Table(name = "contactusers")
public class Contactuser {
    private @Id @GeneratedValue long id;
    private @NotBlank String username;
    private @NotBlank String email;
    private @NotBlank String subject;
    private @NotBlank String message;

//    public Contactuser() {
//    }

//    public Contactuser(@NotBlank String username, @NotBlank String email, @NotBlank String subject, @NotBlank String message)) {
//        this.username = username;
//        this.email = email;
//        this.subject = subject;
//        this.message = message;
//    }

   

	public long getId() {
        return id;
    }

    public void setId(long id) {
		this.id = id;
	}
    
	public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }
    
    public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}


	 public String getSubject() {
			return subject;
		}

		public void setSubject(String subject) {
			this.subject = subject;
		}

		public String getMessage() {
			return message;
		}

		public void setMessage(String message) {
			this.message = message;
		}
}