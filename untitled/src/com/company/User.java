package com.company;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.*;
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
        //LOAD PUBLIC KEY FROM THE CERTIFICATE
        publicKey = certificate.getPublicKey();
        KeyStore keyStore = KeyStore.getInstance("JKS");
        //LOAD PRIVATE RSA KEY FROM KEYSTORE
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
        //WRITE PRIVATE KEY TO A FILE AS REQUIRED
        byte[] privateKeyToFile = privateKey.getEncoded();
        FileOutputStream fos = new FileOutputStream(Main.CER_FOLDER+"PRIV-"+userName);
        fos.write(privateKeyToFile);
        fos.close();
    }

    public void logOut() throws InterruptedException {
        //REMOVE PRIVATE KEY FROM FILE WHERE CERTIFICATES ARE STORED
        System.out.println("LOGGING OUT...");
        Thread.sleep(1500);
        File file = new File(Main.CER_FOLDER+"PRIV-"+userName);
        file.delete();
    }

    public void uploadDocument(String path) throws Exception {
        Random random = new Random();
        int documentParts = random.nextInt(4) + Main.MIN_PARTS_OF_DOCUMENT;

        Path realPath = Paths.get(path);
        String[] split = path.split("/");
        String originalPathName = split[split.length - 1].substring(0, split[split.length-1].length()-4);

        //PICTURES ENABLED (ONLY JPG)
        boolean isPicture = false;
        if(path.endsWith(".jpg")) {
            isPicture = true;
        }

        if(checkIfDocumentExists(originalPathName)) {
            throw new Exception("Sorry, but you've already uploaded a document with the same name!");
        }

        try {
            byte[] fileContent = Files.readAllBytes(realPath);
            if(fileContent.length < documentParts) {
                documentParts = fileContent.length;
            }
            byte[] separateDocuments = new byte[documentParts];
            int i = 0;
            int k = 0;

            //DECRYPT KEY FROM FILE (KEY WAS ENCRYPTED WITH PUBLIC RSA KEY)
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.PRIVATE_KEY, privateKey);
            byte[] decryptedKey = cipher.doFinal(encryptedKey);

            SecretKey originalKey = new SecretKeySpec(decryptedKey , 0, decryptedKey .length, "AES");
            aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, originalKey);
            List<byte[]> signedMessages = new ArrayList<>();

            int partSize = fileContent.length / documentParts;
            int contentCounter = 0;

            String directory = "dir";
            int dirNum = 1;
            new File(Main.REPOSITORIUM_FOLDER+userName).mkdir();
            new File("./"+userName+"h").mkdir();
            for(int j = 0; j < separateDocuments.length; j++) {
                new File(Main.REPOSITORIUM_FOLDER+userName+"/"+directory+dirNum++).mkdir();

            }
            dirNum=1;
            while(i < documentParts) {
                byte[] bytes;
                int tempSize = 0;
                if (i == documentParts - 1) {
                    for(int j = contentCounter; j < fileContent.length; j++) {
                        tempSize++;
                    }
                }
                else {
                    tempSize = partSize;
                }
                bytes = new byte[tempSize];
                    for(int j = contentCounter; j < contentCounter+tempSize; j++) {
                        bytes[k] = fileContent[j];
                        k++;
                    }
                    k=0;
                    contentCounter += tempSize;

                //SIGN DOCUMENT (SHA256 WITH RSA)
                Signature signature = Signature.getInstance("SHA256withRSA");
                //SIGN WITH USERS PRIVATE KEY
                signature.initSign(privateKey);
                signature.update(bytes);
                byte[] signedMessage = signature.sign();
                //ENCRYPT DOCUMENT
                byte[] encryptedMessage = aesCipher.doFinal(bytes);
                signedMessages.add(signedMessage);

                String pathString = Main.REPOSITORIUM_FOLDER+userName+"/dir"+dirNum+"/"+originalPathName+Main.SPECIAL_SIGN+String.valueOf(dirNum);
                String pathString2 = "./"+userName+"h/"+originalPathName+Main.SPECIAL_SIGN+String.valueOf(dirNum);
                if(isPicture) {
                    //JUST SO I KNOW IF I'M READING A PICTURE OR I'M NOT
                    pathString+="jpg";
                    pathString2+="jpg";
                }
                //WRITE HASH AND ENCRYPTED MESSAGE
                Path path1 = Paths.get(pathString + ".txt");
                Files.write(path1, encryptedMessage);
                Files.write(Paths.get(pathString2 +".txt"), signedMessage);
                dirNum++;
                i++;
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    public void downloadDocument() throws Exception {
        try {
            Scanner scanner = new Scanner(System.in);
            String document;
            System.out.println("Which document do you want to download: ");
            document = scanner.nextLine();
            boolean isValid = validateDocument(document);
            //System.out.println("validateee");
            for(String f : files) {
                System.out.println(f);
            }
            boolean isPicture = false;
            for(String raw : rawFiles) {
                if(raw.contains("jpg") && raw.contains(document)) {
                    isPicture = true;
                }
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

            //STORE DOCUMENT IN DOWNLOADS FOLDER
            //PROBABLY BAD IDEA BECAUSE NOT EVERYHONE HAS DOWNLOADS (LINUX...)
            System.out.println("DOCUMENT WILL BE STORED IN YOUR DOWNLOADS FOLDER!");
            String home = System.getProperty("user.home");
            File downloadsFolder = new File(home+"/Downloads/"+document);

            if(isPicture) {
                //PROCESS PICTURE AND SAVE IT AS A PICTURE
                int fullLength = 0;
                for(int i = 0; i < bytesContent.size(); i++) {
                    fullLength += bytesContent.get(i).length;
                }
                int k = 0;
                byte[] realData = new byte[fullLength];
                for(int i = 0; i < bytesContent.size(); i++) {
                    for(int j = 0; j < bytesContent.get(i).length; j++) {
                        realData[k++] = bytesContent.get(i)[j];
                    }
                }
                ByteArrayInputStream bis = new ByteArrayInputStream(realData);
                BufferedImage bufferedImage = ImageIO.read(bis);
                ImageIO.write(bufferedImage, "jpg", new File(downloadsFolder.toString()+".jpg"));
                //System.out.println("Image IN!");
            }
            else {
                //ELSE SAVE IT AS A TXT FILE
                BufferedWriter writer = new BufferedWriter(new FileWriter(downloadsFolder+".txt"));
                for(int i = 0; i < bytesContent.size(); i++) {
                    fullContent += new String(bytesContent.get(i));
                }
                writer.write(fullContent);
                writer.close();
                //System.out.println("Image OUT!");
            }
            fullContent = "";
            bytesContent.clear();
        } catch (Exception e) {
            System.out.println("Document has been corrupted!!!");
        }

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
    private Set<String> rawFiles = new HashSet<>();
    public void listDocumentsForReal() {
        //SHOULD BE USER NAME IMPLEMENTED
        new File("./"+userName+"h/").mkdir();
        File helpDir = new File("./"+userName+"h/");
        String[] listFiles = helpDir.list();
        for(String s : listFiles)  {
            String[] split = s.split("-");
            //System.out.println("STR="+s);
            if(!files.contains(split[0]))
            {
                rawFiles.add(s);
                files.add(split[0]);
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
    private List<byte[]> bytesContent = new ArrayList<>();
    private boolean validateDocument(String document) throws Exception {
        //DECRYPT SYMMETRIC KEY
        boolean isValid = true;
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.PRIVATE_KEY, privateKey);
        byte[] decryptedKey = cipher.doFinal(encryptedKey);
        SecretKey originalKey = new SecretKeySpec(decryptedKey , 0, decryptedKey .length, "AES");
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        //DECIPHER MODE ON
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
                        //READ CONTENT AND TRY TO DECRYPT IT
                        byte[] readContent = Files.readAllBytes(Paths.get(path));
                        byte[] bytePlainText = aesCipher.doFinal(readContent);
                        //System.out.println("PLAIN TEXT = " + new String(bytePlainText));
                        //fullContent += new String(bytePlainText);
                        bytesContent.add(bytePlainText);
                        File hashDir = new File("./"+userName+"h/");
                        String[] hashes = hashDir.list();
                        for(String h : hashes) {
                            String[] hashSpliter = h.split(Main.SPECIAL_SIGN);
                            String hash = hashSpliter[0];
                            if(hash.equals(file)) {
                                hashCounter++;
                                if(hashCounter == fileCounter) {
                                    //System.out.println("FC = " + fileCounter);
                                    //System.out.println("HC = " + hashCounter);
                                    String pathH = "./"+userName+"h/"+h;
                                    FileInputStream fis = new FileInputStream(pathH);
                                    byte[] readHash = new byte[512];
                                    //TRY TO VERIFY FILE
                                    fis.read(readHash);
                                    fis.close();
                                    Signature signature = Signature.getInstance("SHA256withRSA");
                                    signature.initVerify(publicKey);
                                    signature.update(bytePlainText);
                                    boolean valid = signature.verify(readHash);
                                    if(!valid) {
                                        //IF IT'S BAD, THROW EXCEPTION
                                        throw new Exception("INVALID DOCUMENT!");
                                        //isValid = false;
                                    }
                                    //System.out.println("VALID: " + valid);
                                }

                            }

                        }
                    }
                }
            }
        }
        //IF IT'S GOOD -> RETURN TRUE
        return isValid;
    }
}
