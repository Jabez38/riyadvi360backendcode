package registerandlogin.user;


import java.awt.print.Pageable;
import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


public interface UserRepository1 extends JpaRepository < TilesImage, Long  > {

	void save(GlbModel glbmodel);
	
	void save(webpageimg webpageimg);

	List<TilesImage> findByFileUrlIn(List<String> fileUrls);

	Page<TilesImage> findByuserid(Long userid, org.springframework.data.domain.Pageable pageable);

	

	

	

//	TilesImage findByUserid(Object object);

//	TilesImage findByUserid(Object object);

	



	











	



	









	

	

	

	


	

	



	

	





	

	


    
}