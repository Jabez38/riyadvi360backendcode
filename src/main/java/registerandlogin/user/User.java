package registerandlogin.user;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.validation.constraints.NotBlank;

import java.sql.Date;
import java.time.LocalDateTime;
import java.util.Objects;

@Entity
@Table(name = "users")
public class User {
    private @Id @GeneratedValue long id;
    private @NotBlank String username;
    private @NotBlank String email;
    private @NotBlank String password;
    
    private @NotBlank String payamount;
    private @NotBlank boolean loggedIn;
    private @NotBlank String otp;
    private @NotBlank Date otpExpiry;
    private LocalDateTime newPriceSetTime; 
    private String defaultPayamount; // Add this field to store the original pay amount




	public User() {
    }

    public User(@NotBlank String username, @NotBlank String email, @NotBlank String password) {
        this.username = username;
        this.email = email;
        this.password = password;
        this.loggedIn = false;
    }

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


	public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
    public String getPayamount() {
  		return payamount;
  	}

  	public void setPayamount(String payamount) {
  		this.payamount = payamount;
  	}

    public boolean isLoggedIn() {
        return loggedIn;
    }

    public void setLoggedIn(boolean loggedIn) {
        this.loggedIn = loggedIn;
    }

    public String getOtp() {
        return otp;
    }
    
    public void setOtp(String otp) {
        this.otp = otp;
    }
    
    public Date getOtpExpiry() {
        return otpExpiry;
    }
    
    public void setOtpExpiry(Date otpExpiry) {
        this.otpExpiry = otpExpiry;
    }
    
    public LocalDateTime getNewPriceSetTime() {
        return newPriceSetTime;
    }

    public void setNewPriceSetTime(LocalDateTime newPriceSetTime) {
        this.newPriceSetTime = newPriceSetTime;
    }
    
    public String getDefaultPayamount() {
        return defaultPayamount;
    }

    public void setDefaultPayamount(String defaultPayamount) {
        this.defaultPayamount = defaultPayamount;
    }
  
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof User)) return false;
        User user = (User) o;
        return Objects.equals(username, user.username) &&
                Objects.equals(email, user.email) && Objects.equals(password, user.password);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, username, email, password, loggedIn);
    }

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", email='" + email + '\'' +
                ", password='" + password + '\'' +
                ", loggedIn=" + loggedIn +
                '}';
    }


}
