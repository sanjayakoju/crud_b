package com.cruddemo.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.multipart.MultipartFile;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

public class FileUpload {

    @Value("${file.upload-directory}")
    static String name;

    public static void upload(MultipartFile file, String fileName) throws IOException {
//        if(!file.isEmpty()) {
//            FileOutputStream fileOutputStream = new FileOutputStream("/Users/Sanjaya.Koju/Documents/my project/crud demo b/src/main/resources/static/"+fileName+".jpg");
////            FileOutputStream fileOutputStream = new FileOutputStream(name +fileName+".jpg");
//            fileOutputStream.write(file.getBytes());
//            fileOutputStream.close();
//        }
        Path uploadDirectory = Path.of("/Users/Sanjaya.Koju/Documents/my project/crud demo b/src/main/resources/static/user");
        System.out.println("Path : "+ uploadDirectory);
        try (InputStream inputStream = file.getInputStream()) {
            Path filePath = uploadDirectory.resolve(fileName);
            Files.copy(inputStream, filePath, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException ioException) {
            throw new IOException("Error saving uploaded file :" +fileName , ioException);
        }
    }
}
