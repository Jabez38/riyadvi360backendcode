package registerandlogin.user;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "glbmodel")
public class GlbModel {
	
	
	  @Id
	    @GeneratedValue(strategy = GenerationType.IDENTITY)
	    private Long id;
	    private String fileUrl;
	    private String glbmodel;
	    
		public Long getId() {
			return id;
		}
		public void setId(Long id) {
			this.id = id;
		}
		public String getFileUrl() {
			return fileUrl;
		}
		public void setFileUrl(String fileUrl) {
			this.fileUrl = fileUrl;
		}
		
		public String getGlbmodel() {
			return glbmodel;
		}
		public void setGlbmodel(String glbmodel) {
			this.glbmodel = glbmodel;
		}
	    
	  
}