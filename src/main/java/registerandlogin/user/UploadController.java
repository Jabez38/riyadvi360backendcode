package registerandlogin.user;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.DeleteObjectRequest;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.mysql.cj.result.Row;







@CrossOrigin(origins = "*")
@RestController
public class UploadController {
	@Autowired
    private UserRepository1 userRepository;
	@Autowired
    private UserRepositoryDelete userRepositorydelete;
//	@Autowired
//	 private itemservice Itemservice;
	
	@Autowired
	private AmazonS3 s3client;
	
	@Value("${endpointUrl}")
    private String endpointUrl;
	
    @Value("${bucketName}")
    private String bucketName;

    @GetMapping("/list1")
	public List<TilesImage> floortiles( ) {
    	
    	List<TilesImage> floorimage = userRepository.findAll();
    	
   		return floorimage;
   
    }   
		
//    @GetMapping("/users")
//    public List<TilesImage> getUsers(int page, int size) {
//        Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Order.desc("uploadTimestamp")));
//        Page<TilesImage> page1 = userRepository.findAll(pageable);
//        return page1.getContent();
//    }

    @GetMapping("/users")
    public List<TilesImage> getUsers( @RequestParam int page,  @RequestParam int size) {
    	Pageable pageable = PageRequest.of(page, size);
    	 System.out.println(pageable);
        Page<TilesImage> page1 = userRepository.findAll(pageable);     
        System.out.println(page1.getContent());
        return page1.getContent();
    }
    
//    @GetMapping("/users")
//    public List<TilesImage> getUsers(@RequestParam Long userid,
//                                     @RequestParam int page,
//                                     @RequestParam int size) {
//        Pageable pageable = PageRequest.of(page, size);
//        Page<TilesImage> page1 = userRepository.findByuserid(userid, pageable);
//        return page1.getContent();
//    }
    
    

    
    
    

    @DeleteMapping("/delete")
    public ResponseEntity<String> deleteImages(@RequestBody List<String> fileUrls) {
    	
        List<TilesImage> images = userRepository.findByFileUrlIn(fileUrls);
        
        userRepository.deleteAll(images);
        String region = "ap-south-1"; // Replace with your desired region

        String accessKey = "AKIA2IZ54UXNUYTKBVFG";
        String secretKey = "RZlxVBigSxTVLtuOJCbNm1dLKT6MVrHnmhQ4QJH6";

        BasicAWSCredentials credentials = new BasicAWSCredentials(accessKey, secretKey);

        
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
            .withCredentials(new AWSStaticCredentialsProvider(credentials))
            .withRegion(region)
            .build();
        
        String bucketName = "jabez-tiles"; // Replace with the actual name of your S3 bucket
        
        for (String fileUrl : fileUrls) {
            // Extract the key from the S3 URL
            String key = fileUrl.substring(fileUrl.lastIndexOf('/') + 1);
            
            // Delete the object from the S3 bucket
            s3Client.deleteObject(new DeleteObjectRequest(bucketName, key));
        }
        
        return ResponseEntity.ok("Images deleted successfully");
    }

    
       
    public  String fileUrl = "";
    public String  status = null;
    public String tilesdesign = "tilesimages";
    public String images = "img";
    public String wall = "walltiles";
    public String glb = "glbfile";
    
      @PostMapping("/list")
      public String floorupload(  @RequestParam("file") MultipartFile[] multipartFile,
              @RequestParam("userid") Long userid) {
      	
      	  try {
      		 Arrays.asList(multipartFile).stream().forEach(file -> {
              	 File filess;
  				try {
  					filess = convertMultiPartToFile(file);
  					 
  	            	 String fileName = file.getOriginalFilename();

  	     		fileUrl = endpointUrl + "/" + fileName;
  	     		System.out.println(fileUrl);
  	     		status = uploadFileTos3bucket(fileName, filess);

  	     		filess.delete();
  	     		
  	     		
  	     		TilesImage user = new TilesImage();		     		
  	  	            user.setFileUrl(fileUrl);
  	  	            user.setTiles(tilesdesign);	  
  	  	        user.setUploadTimestamp(new Date());
  	  	        user.setUserid(userid);
  	  	            userRepository.save(user);
 	     	     		
  				}
  				
  				catch (IOException e) {
  					// TODO Auto-generated catch block
  					e.printStackTrace();
  				}
              
               });  		
      	} 
      	
      	catch (Exception e) { 

      		return "UploadController().uploadFile().Exception : " + e.getMessage();
      	}

      	
      	return status;
      } 
      
      
      
      @PostMapping("/listimg")
      public String filesimageupload(  @RequestParam("file") MultipartFile[] multipartFiles) {
      	
      	  try {
      		 Arrays.asList(multipartFiles).stream().forEach(file -> {
              	 File filess;
  				try {
  					filess = convertMultiPartToFile(file);
  					 
  	            	 String fileName = file.getOriginalFilename();

  	     		fileUrl = endpointUrl + "/" + fileName;
  	     		System.out.println(fileUrl);
  	     		status = uploadFileTos3bucket(fileName, filess);

  	     		filess.delete();
  	     		
  	     		
  	     		webpageimg user = new webpageimg();		     		
  	  	            user.setFileUrl(fileUrl);
  	  	            user.setImages(images);	  
  	  	      
  	  	   
  	  	            userRepository.save(user);
 	     	     		
  				}
  				
  				catch (IOException e) {
  					// TODO Auto-generated catch block
  					e.printStackTrace();
  				}
              
               });  		
      	} 
      	
      	catch (Exception e) { 

      		return "UploadController().uploadFile().Exception : " + e.getMessage();
      	}

      	
      	return status;
      } 
      
      
      
      @PostMapping("/list3")
      public String glbupload(@RequestParam("file") MultipartFile[] multipartFile) {
      	
    	  try {
       		 Arrays.asList(multipartFile).stream().forEach(file -> {
               	 File filess;
   				try {
   					filess = convertMultiPartToFile(file);
   					 
   	            	 String fileName = file.getOriginalFilename();

   	     		fileUrl = endpointUrl + "/" + fileName;
   	     		System.out.println(fileUrl);
   	     		status = uploadFileTos3bucket(fileName, filess);

   	     		filess.delete();
   	     		
   	     		if(fileName.contains("glb") || fileName.contains("gltf")) {
   	     		GlbModel glbmodel = new GlbModel();
   	     		 glbmodel.setFileUrl(fileUrl);
   	     		glbmodel.setGlbmodel(glb);	            
 	  	            userRepository.save(glbmodel);
  	     		}
   	     				
   	            
   				}
   				
   				catch (IOException e) {
   					// TODO Auto-generated catch block
   					e.printStackTrace();
   				}
               
                });  		
       	} 
       	
       	catch (Exception e) { 

       		return "UploadController().uploadFile().Exception : " + e.getMessage();
       	}

       	
       	return status;
       } 
      
      
      private File convertMultiPartToFile(MultipartFile file) throws IOException {
      	File convFile = new File(file.getOriginalFilename());
      	FileOutputStream fos = new FileOutputStream(convFile);
      	fos.write(file.getBytes());
      	fos.close();
      	return convFile;
      }


      private String uploadFileTos3bucket(String fileName, File file) {
      	try {
      		s3client.putObject(new PutObjectRequest(bucketName, fileName, file));
      	}catch(AmazonServiceException e) {
      		return "uploadFileTos3bucket().Uploading failed :" + e.getMessage(); 
      	}
      	return "Uploading Successfull -> ";
      }
     
          
  }


