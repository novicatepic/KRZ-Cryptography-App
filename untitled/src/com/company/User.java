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
            List<byte[]> signedMessages = new ArrayList<>();
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
                //ENCRYPT DOCUMENT
                byte[] encryptedMessage = aesCipher.doFinal(separateDocuments[i].getBytes(StandardCharsets.UTF_8));
                signedMessages.add(signedMessage);
                separateDocuments[i] = Base64.getEncoder().encodeToString(encryptedMessage);
                i++;
            }

            //SIGN DOCUMENT
            //ENCRYPT WITH AES
            //ENCODE MESSAGE TO  BASE64 STRING

            String directory = "dir";
            int dirNum = 1;
            for(int j = 0; j < separateDocuments.length; j++) {
                new File("./"+directory+dirNum++).mkdir();
                new File("./NOCOh").mkdir();
            }

            dirNum = 1;
            for(int j = 0; j < separateDocuments.length; j++) {
                BufferedWriter f_writer
                        = new BufferedWriter(new FileWriter(
                        "./dir"+dirNum+"/"+originalPathName+String.valueOf(j+1) + ".txt"));
                f_writer.write(separateDocuments[j]);
                f_writer.close();
                Files.write(Paths.get("./NOCOh/"+originalPathName+ String.valueOf(j+1) +".txt"), signedMessages.get(j));
                dirNum++;
            }


        } catch (Exception e) {
            System.out.println(e.getMessage());
            System.out.println("FILE EXCEPTION!");
        }
    }

    public void downloadDocument() throws Exception {
        Scanner scanner = new Scanner(System.in);
        String document;
        System.out.println("Which document do you want to download: ");
        document = scanner.nextLine();
        boolean isValid = validateDocument(document);
        if(!files.contains(document)) {
            System.out.println("THAT DOCUMENT DOES NOT EXIST!!!");
            return;
        }
        if(!isValid) {
            String extraInput;
            System.out.println("WARNING: DOCUMENT WAS CHANGED!!!\nAre you sure that you want to continue (y/n)");
            extraInput = scanner.nextLine();
            if("n".equalsIgnoreCase(extraInput)) {
                return;
            }
        }
        System.out.println("DOCUMENT WILL BE STORED IN YOUR DOWNLOADS FOLDER!");
        String home = System.getProperty("user.home");
        File downloadsFolder = new File(home+"/Downloads/"+document+".txt");

        BufferedWriter writer = new BufferedWriter(new FileWriter(downloadsFolder));
        writer.write(fullContent);
        writer.close();
        fullContent = "";
    }


    private Set<String> files = new HashSet<>();
    public void listDocumentsForReal() {
        //SHOULD BE USER NAME IMPLEMENTED
        File helpDir = new File("./NOCOh/");
        String[] listFiles = helpDir.list();
        //Set<String> files = new HashSet<>();
        boolean first = true;
        for(String file : listFiles) {
            String helper = file.substring(0, file.length()-5);
            if(first) {
                files.add(helper);
                first = false;
            }
            else {
                for(String f : files) {
                    if(!file.contains(f)) {
                        files.add(helper);
                    }
                }
            }
        }

        //PRINT DOCUMENTS
        System.out.println("=== YOUR DOCUMENT LIST ===");
        System.out.println("==========================");
        System.out.println("==========================");
        System.out.println("==========================");
        for(String printer : files) {
            System.out.println(printer);
        }
        System.out.println("==========================");
        System.out.println("==========================");
        System.out.println("==========================");
    }

    private String fullContent = "";
    private boolean validateDocument(String document) throws Exception {
        boolean isValid = true;
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.PRIVATE_KEY, privateKey);
        byte[] decryptedKey = cipher.doFinal(encryptedKey);

        SecretKey originalKey = new SecretKeySpec(decryptedKey , 0, decryptedKey .length, "AES");
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesCipher.init(Cipher.DECRYPT_MODE, originalKey);

        File workingDirectory = new File("./");
        String[] contents = workingDirectory.list();

        for(String folder : contents) {
            if(folder != null && folder.contains("dir")) {
                File openFolder = new File("./"+folder);
                String[] folderContents = openFolder.list();

                for(String file : folderContents) {
                    if(file.contains(document)) {
                        String path = "./"+folder+"/"+file;
                        String readContent = Files.readString(Paths.get(path));
                        //System.out.println("CONTENT " + readContent);
                        byte[] signedMessage = Base64.getDecoder().decode(readContent);
                        byte[] bytePlainText = aesCipher.doFinal(signedMessage);
                        fullContent += new String(bytePlainText);
                        File hashDir = new File("./NOCOh/");
                        String[] hashes = hashDir.list();
                        for(String hash : hashes) {
                            if(hash.equals(file)) {
                                //System.out.println("GOOOOO");
                                String pathH = "./NOCOh/"+hash;
                                FileInputStream fis = new FileInputStream(pathH);
                                byte[] readHash = new byte[256];
                                fis.read(readHash);
                                fis.close();
                                Signature signature = Signature.getInstance("SHA256withRSA");
                                signature.initVerify(publicKey);
                                signature.update(bytePlainText);
                                boolean valid = signature.verify(readHash);
                                if(!valid) {
                                    isValid = false;
                                }
                                //System.out.println("VALID: " + valid);
                            }
                        }

                    }
                }
            }
        }
        //System.out.println("VALIDATED: " + isValid);
        return isValid;
    }

    public void listDocuments() throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.PRIVATE_KEY, privateKey);
        byte[] decryptedKey = cipher.doFinal(encryptedKey);

        SecretKey originalKey = new SecretKeySpec(decryptedKey , 0, decryptedKey .length, "AES");
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesCipher.init(Cipher.DECRYPT_MODE, originalKey);

        File workingDirectory = new File("./");
        String[] contents = workingDirectory.list();

        for(String folder : contents) {
            if(folder != null && folder.contains("dir")) {
                File openFolder = new File("./"+folder);
                String[] folderContents = openFolder.list();

                for(String file : folderContents) {
                    String path = "./"+folder+"/"+file;
                    String readContent = Files.readString(Paths.get(path));
                    //System.out.println("CONTENT " + readContent);
                    byte[] signedMessage = Base64.getDecoder().decode(readContent);
                    //System.out.println("SIG " + signedMessage);

                    byte[] bytePlainText = aesCipher.doFinal(signedMessage);
                    System.out.println(new String(bytePlainText));

                    File hashDir = new File("./NOCOh/");
                    String[] hashes = hashDir.list();
                    for(String hash : hashes) {
                        if(hash.equals(file)) {
                            //System.out.println("GOOOOO");
                            String pathH = "./NOCOh/"+hash;
                            FileInputStream fis = new FileInputStream(pathH);
                            byte[] readHash = new byte[256];
                            fis.read(readHash);
                            System.out.println("READ: "+ readHash);

                            fis.close();
                            Signature signature = Signature.getInstance("SHA256withRSA");
                            signature.initVerify(publicKey);
                            signature.update(bytePlainText);
                            System.out.println("SUP");
                            boolean valid = signature.verify(readHash);
                            //System.out.println("VALID: " + valid);
                        }
                    }
                }

            }
        }

    }




    public void testFunc() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128); // The AES key size in number of bits
        secKey = generator.generateKey();
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, secKey);

        //START
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.PUBLIC_KEY, publicKey);
        encryptedKey = cipher.doFinal(secKey.getEncoded());
        //END
        //START2
        Cipher cipherD = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipherD.init(Cipher.PRIVATE_KEY, privateKey);
        byte[] decryptedKey = cipherD.doFinal(encryptedKey);

        SecretKey originalKey = new SecretKeySpec(decryptedKey , 0, decryptedKey .length, "AES");
        Cipher aesCipherD = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesCipherD.init(Cipher.DECRYPT_MODE, originalKey);
        //END2

        //ADDED SIGN
        String message = "Hello world";
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signedMessage = signature.sign();
        byte[] encryptedMessage = aesCipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        String blah =  Base64.getEncoder().encodeToString(encryptedMessage);

        byte[] decoded =  Base64.getDecoder().decode(blah);
        //System.out.println("==================");
        //System.out.println("DECODED: " + new String(decoded));
        aesCipher.init(Cipher.DECRYPT_MODE, secKey);
        byte[] bytePlainText = aesCipherD.doFinal(decoded);

        Signature signature2 = Signature.getInstance("SHA256withRSA");
        signature2.initVerify(publicKey);
        signature2.update(bytePlainText);
        boolean valid = signature2.verify(signedMessage);
        System.out.println("VALID: " + valid);

    }


}
