package registerandlogin.user;

import java.util.Date;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;



@Entity
	@Table(name = "tilesimage")
	public class TilesImage {

	    @Id
	    @GeneratedValue(strategy = GenerationType.IDENTITY)
	    private Long id;
	    private String fileUrl;
	    private String tiles;   
	    private Long userid;
	    private Date uploadTimestamp;
	   
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
	
		public String getTiles() {
			return tiles;
		}
		public void setTiles(String tiles) {
			this.tiles = tiles;
		}
		public Long getUserid() {
			return userid;
		}
		public void setUserid(Long userid) {
			this.userid = userid;
		}
		public Date getUploadTimestamp() {
			return uploadTimestamp;
		}
		public void setUploadTimestamp(Date uploadTimestamp) {
			this.uploadTimestamp = uploadTimestamp;
		}
	

}
