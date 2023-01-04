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
    byte[] encryptedKey = new byte[512];
    PrivateKey privateKey;
    PublicKey publicKey;
    Cipher aesCipher;
    private X509Certificate certificate;

    public User(String uN, String p, X509Certificate certificate) throws Exception {
        Scanner scanner = new Scanner(System.in);
        userName = uN;
        password = p;
        this.certificate = certificate;
        publicKey = certificate.getPublicKey();
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (InputStream inputStream = new FileInputStream(Main.CER_FOLDER+"keystore.jks")) {
            keyStore.load(inputStream, KeyStoreCreator.KEY_STORE_PASSWORD.toCharArray());
        }
        System.out.println("Enter a password for your private key: ");
        String passInput = scanner.nextLine();
        privateKey = (PrivateKey) keyStore.getKey(userName, passInput.toCharArray());
        FileInputStream fis = new FileInputStream(Main.keyPath+"/"+userName);
        fis.read(encryptedKey);
        //System.out.println("ENCRYPTED KEY = " + new String(encryptedKey));
        fis.close();
        byte[] privateKeyToFile = privateKey.getEncoded();
        FileOutputStream fos = new FileOutputStream(Main.CER_FOLDER+"PRIV-"+userName);
        fos.write(privateKeyToFile);
        fos.close();
    }

    public void logOut() throws InterruptedException {
        System.out.println("LOGGING OUT...");
        Thread.sleep(1500);
        File file = new File(Main.CER_FOLDER+"PRIV-"+userName);
        file.delete();
    }

    public String getUserName() {
        return userName;
    }

    public String getPassword() {
        return password;
    }

    public void uploadDocument(String path) throws Exception {
        Random random = new Random();
        int documentParts = random.nextInt(4) + Main.MIN_PARTS_OF_DOCUMENT;

        Path realPath = Paths.get(path);
        String[] split = path.split("/");
        String originalPathName = split[split.length - 1].substring(0, split[split.length-1].length()-4);

        if(checkIfDocumentExists(originalPathName)) {
            throw new Exception("Sorry, but you've already uploaded a document with the same name!");
        }

        try {
            List<String> fileContent = Files.readAllLines(realPath);
            if(fileContent.size() < documentParts) {
                documentParts = fileContent.size();
            }
            String[] separateDocuments = new String[documentParts];

            for(int i = 0; i < separateDocuments.length; i++) {
                separateDocuments[i] = "";
            }

            int numLines = fileContent.size();
            int separator = numLines / documentParts;
            int i = 0;
            int k = 0;
            /*KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(128); // The AES key size in number of bits
            SecretKey secKey = generator.generateKey();
            Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, secKey);
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.PUBLIC_KEY, publicKey);
            encryptedKey = cipher.doFinal(secKey.getEncoded());*/
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.PRIVATE_KEY, privateKey);
            byte[] decryptedKey = cipher.doFinal(encryptedKey);

            SecretKey originalKey = new SecretKeySpec(decryptedKey , 0, decryptedKey .length, "AES");
            aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, originalKey);
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
            new File(Main.REPOSITORIUM_FOLDER+userName).mkdir();
            new File("./"+userName+"h").mkdir();
            for(int j = 0; j < separateDocuments.length; j++) {
                new File(Main.REPOSITORIUM_FOLDER+userName+"/"+directory+dirNum++).mkdir();

            }

            dirNum = 1;
            for(int j = 0; j < separateDocuments.length; j++) {
                BufferedWriter f_writer
                        = new BufferedWriter(new FileWriter(
                        Main.REPOSITORIUM_FOLDER+userName+"/dir"+dirNum+"/"+originalPathName+Main.SPECIAL_SIGN+String.valueOf(j+1) + ".txt"));
                f_writer.write(separateDocuments[j]);
                f_writer.close();
                Files.write(Paths.get("./"+userName+"h/"+originalPathName+Main.SPECIAL_SIGN+String.valueOf(j+1) +".txt"), signedMessages.get(j));
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
        System.out.println("validateee");
        for(String f : files) {
            System.out.println(f);
        }
        /*if(!files.contains(document)) {
            System.out.println("THAT DOCUMENT DOES NOT EXIST!!!");
            return;
        }*/
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

    private boolean checkIfDocumentExists(String document) {
        boolean exists = false;

        for(String doc : files) {
            if(doc.equals(document)) {
                exists = true;
            }
        }

        return exists;
    }

    private Set<String> files = new HashSet<>();
    public void listDocumentsForReal() {
        //SHOULD BE USER NAME IMPLEMENTED
        new File("./"+userName+"h/").mkdir();
        File helpDir = new File("./"+userName+"h/");
        String[] listFiles = helpDir.list();
        for(String s : listFiles)  {
            String[] split = s.split("-");
            if(!files.contains(split[0]))
            {
                files.add(split[0]);
            }

        /*boolean first = true;
        if(listFiles != null) {
            for(String file : listFiles) {
                String helper = file.substring(0, file.length()-6);
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
            }*/


        }
        /*else {
            System.out.println("YOU DON'T HAVE ANY FILES YET");
        }*/
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
        boolean finalValidation = true;
        boolean isValid = true;
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.PRIVATE_KEY, privateKey);
        byte[] decryptedKey = cipher.doFinal(encryptedKey);
        SecretKey originalKey = new SecretKeySpec(decryptedKey , 0, decryptedKey .length, "AES");
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesCipher.init(Cipher.DECRYPT_MODE, originalKey);

        File workingDirectory = new File(Main.REPOSITORIUM_FOLDER+userName+"/");
        String[] contents = workingDirectory.list();
        int fileCounter = 0;
        for(String folder : contents) {

            if(folder != null && folder.contains("dir")) {
                File openFolder = new File(Main.REPOSITORIUM_FOLDER+userName+"/"+folder);
                String[] folderContents = openFolder.list();


                int hashCounter = 0;
                for(String fi : folderContents) {
                    String[] split = fi.split(Main.SPECIAL_SIGN);
                    String file = split[0];
                    if(file.equals(document)) {
                        fileCounter++;
                        hashCounter = 0;
                        String path = Main.REPOSITORIUM_FOLDER+userName+"/"+folder+"/"+fi;
                        String readContent = Files.readString(Paths.get(path));
                        //System.out.println("CONTENT " + readContent);
                        byte[] signedMessage = Base64.getDecoder().decode(readContent);
                        byte[] bytePlainText = aesCipher.doFinal(signedMessage);
                        fullContent += new String(bytePlainText);
                        File hashDir = new File("./"+userName+"h/");
                        String[] hashes = hashDir.list();
                        boolean atLeastOneValid = false;
                        for(String h : hashes) {

                            String[] hashSpliter = h.split(Main.SPECIAL_SIGN);
                            String hash = hashSpliter[0];
                            if(hash.equals(file)) {
                                hashCounter++;
                                if(hashCounter == fileCounter) {
                                    System.out.println("FC = " + fileCounter);
                                    System.out.println("HC = " + hashCounter);
                                    String pathH = "./"+userName+"h/"+h;
                                    FileInputStream fis = new FileInputStream(pathH);
                                    byte[] readHash = new byte[512];
                                    fis.read(readHash);
                                    fis.close();
                                    Signature signature = Signature.getInstance("SHA256withRSA");
                                    signature.initVerify(publicKey);
                                    signature.update(bytePlainText);
                                    boolean valid = signature.verify(readHash);
                                    if(!valid) {
                                        isValid = false;
                                    }
                                /*else {
                                    atLeastOneValid = true;
                                }*/
                                    System.out.println("VALID: " + valid);
                                }

                            }

                        }
                        /*if(atLeastOneValid) {
                            isValid = true;
                            atLeastOneValid = false;
                        }
                        else {
                            finalValidation = false;
                        }*/
                        //System.out.println("VALID: " + isValid);
                    }
                }
            }
        }
        //System.out.println("VALIDATED: " + isValid);
        return isValid;
    }

    /*public void listDocuments() throws Exception {
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

                    File hashDir = new File("./"+userName+"h/");
                    String[] hashes = hashDir.list();
                    for(String hash : hashes) {
                        if(hash.equals(file)) {
                            //System.out.println("GOOOOO");
                            String pathH = "./"+userName+"h/"+hash;
                            FileInputStream fis = new FileInputStream(pathH);
                            byte[] readHash = new byte[512];
                            fis.read(readHash);
                            System.out.println("READ: "+ readHash);

                            fis.close();
                            Signature signature = Signature.getInstance("SHA256withRSA");
                            signature.initVerify(publicKey);
                            signature.update(bytePlainText);
                            System.out.println("SUP");
                            boolean valid = signature.verify(readHash);
                            System.out.println("VALID: " + valid);
                        }
                    }
                }

            }
        }

    }*/




    /*public void testFunc() throws Exception {
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

    }*/


}
