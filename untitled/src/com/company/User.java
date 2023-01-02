package com.company;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.*;

public class User {

    private String userName;
    private String password;
    byte[] encryptedKey;
    PrivateKey privateKey;
    PublicKey publicKey;
    //Cipher aesCipher;
    SecretKey secKey;

    public User() {

    }

    public User(String uN, String p) {
        userName = uN;
        password = p;
    }

    public String getUserName() {
        return userName;
    }

    public String getPassword() {
        return password;
    }

    //IN WORKS FOR NOW!
    public void uploadDocument(String path, X509Certificate certificate) {
        Random random = new Random();

        int documentParts = Main.MIN_PARTS_OF_DOCUMENT;

        Path realPath = Paths.get(path);
        String[] split = path.split("/");
        String originalPathName = split[split.length - 1].substring(0, split[split.length-1].length()-4);
        List<File> files = new ArrayList<>();

        try {
            List<String> fileContent = Files.readAllLines(realPath);
            String[] separateDocuments = new String[documentParts];

            for(int i = 0; i < separateDocuments.length; i++) {
                separateDocuments[i] = "";
            }

            publicKey = certificate.getPublicKey();
            //SHOULD IMPLEMENT INPUT HERE, FOR PRIVATE KEY!
            KeyStore keyStore = KeyStore.getInstance("JKS");
            try (InputStream inputStream = new FileInputStream("keystore.jks")) {
                keyStore.load(inputStream, KeyStoreCreator.KEY_STORE_PASSWORD.toCharArray());
            }
            privateKey = (PrivateKey) keyStore.getKey("NOCO", "sigurnost".toCharArray());



            int numLines = fileContent.size();
            int separator = numLines / documentParts;
            int i = 0;
            int k = 0;
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(128); // The AES key size in number of bits
            secKey = generator.generateKey();
            Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, secKey);
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.PUBLIC_KEY, publicKey);
            encryptedKey = cipher.doFinal(secKey.getEncoded());
            while(i < documentParts) {
                for(int j = 0; j < separator; j++) {
                    separateDocuments[i] += fileContent.get(k) + "\n";
                    ++k;
                }

                //ADD REST IF LAST
                if(i == documentParts - 1) {
                    for(int j = k; j < fileContent.size(); j++) {
                        separateDocuments[i] += fileContent.get(k) + "\n";
                        ++k;
                    }
                }

                //SIGN DOCUMENT
                Signature signature = Signature.getInstance("SHA256withRSA");
                signature.initSign(privateKey);
                signature.update(separateDocuments[i].getBytes(StandardCharsets.UTF_8));
                byte[] signedMessage = signature.sign();
                //USING AES BECAUSE PROBLEMS HAPPEN

                //ENCRYPT WITH AES

                //System.out.println("AES CIPH1: " + aesCipher);
                byte[] encryptedMessage = aesCipher.doFinal(signedMessage);
                System.out.println("ENCRYPTED " + encryptedMessage);
                //System.out.println("ENCRYPT: "  + encryptedMessage);

                //System.out.println("ENCRYPT: " + secKey.getEncoded());
                separateDocuments[i] = Base64.getEncoder().encodeToString(encryptedMessage);
                System.out.println("BLA1: " + separateDocuments[i]);
                i++;
            }

            //SIGN DOCUMENT
            //ENCRYPT WITH AES
            //ENCODE MESSAGE TO  BASE64 STRING

            String directory = "dir";
            int dirNum = 1;
            for(int j = 0; j < separateDocuments.length; j++) {
                new File("./"+directory+dirNum++).mkdir();
            }

            dirNum = 1;
            for(int j = 0; j < separateDocuments.length; j++) {
                BufferedWriter f_writer
                        = new BufferedWriter(new FileWriter(
                        "./dir"+dirNum+"/"+originalPathName+String.valueOf(j+1) + ".txt"));
                f_writer.write(separateDocuments[j]);
                f_writer.close();
                dirNum++;
            }


        } catch (Exception e) {
            System.out.println(e.getMessage());
            System.out.println("FILE EXCEPTION!");
        }
    }

    public void downloadDocument(String document, String path) {

    }

    public void listDocuments() throws Exception {

        //WORKS :)
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.PRIVATE_KEY, privateKey);
        byte[] decryptedKey = cipher.doFinal(encryptedKey);

        SecretKey originalKey = new SecretKeySpec(decryptedKey , 0, decryptedKey .length, "AES");
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesCipher.init(Cipher.DECRYPT_MODE, originalKey);

        /*aesCipher.init(Cipher.DECRYPT_MODE, secKey);

        System.out.println("AES CIPH2: " + aesCipher);*/

        File workingDirectory = new File("./");
        String[] contents = workingDirectory.list();

        for(String folder : contents) {
            if(folder != null && folder.contains("dir")) {
                File openFolder = new File("./"+folder);
                String[] folderContents = openFolder.list();

                for(String file : folderContents) {
                    String path = "./"+folder+"/"+file;
                    String readContent = Files.readString(Paths.get(path));
                    System.out.println("CONTENT " + readContent);
                    byte[] signedMessage = Base64.getDecoder().decode(readContent);
                    System.out.println("SIG " + signedMessage);

                    byte[] bytePlainText = aesCipher.doFinal(signedMessage);
                    String s = new String(bytePlainText, StandardCharsets.UTF_8);
                    System.out.println(new String(bytePlainText));
                    //String plainText = new String(bytePlainText);
                    //.out.println(plainText);

                    Signature signature = Signature.getInstance("SHA256withRSA");
                    signature.initVerify(publicKey);
                    signature.update(bytePlainText);
                    boolean valid = signature.verify(bytePlainText);
                    System.out.println("VALID: " + valid);
                }

            }
        }

    }


}
