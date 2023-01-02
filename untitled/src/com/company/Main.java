package com.company;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Scanner;

public class Main {

    public static int MIN_PARTS_OF_DOCUMENT = 4;
    CABody caBody;

    public Main() throws Exception {
        caBody = new CABody();
    }

    public static void main(String[] args) /*throws Exception*/ {


        try {
            Main main = new Main();
            //KeyStoreCreator.generateKeyStore();
            /*PKCS10CertificationRequest req = CertificateRequestCreator.makeCertRequest();
            X509Certificate signed = main.caBody.signCertificate(req, "Novica", "123");*/

            /*PKCS10CertificationRequest req = CertificateRequestCreator.makeCertRequest();
            main.caBody.signCertificate(req, "NOCO", "TEPIC");*/

            //main.loadStartForm();

            //KeyStoreCreator.generateKeyStore();

            byte[] data = Files.readAllBytes(new File("NOCO.crt").toPath());
            CertificateFactory factory = CertificateFactory.getInstance("X509");
            Certificate c = factory.generateCertificate(new ByteArrayInputStream(data));
            X509Certificate realCert = (X509Certificate)c;

            User user = new User();
            user.uploadDocument("./lol.txt", realCert);
            user.listDocuments();
            /*PKCS10CertificationRequest req = CertificateRequestCreator.makeCertRequest();

            X509Certificate signed = caBody.signCertificate(req);
            signed.verify(caBody.getPublicKey());
            System.out.println("SIGNED!");*/

            //loadStartForm();

            //caBody.initCrlList();
            /*System.out.println("BEFORE ADDITION");
            main.caBody.addToCrlList(signed);
            System.out.println("WHEN NOT REMOVED");
            main.caBody.getRevokedCertificates();
            System.out.println("WHEN REMOVED");*/
            //main.caBody.removeFromRevokedList(signed);
            //main.caBody.getRevokedCertificates();

            //TESTING PURPOSES FOR NOW
            //writeVerifiedCertificateToAFile(signed);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            System.out.println("NOT SIGNED");
        }
        //System.out.println(casted.getSubjectDN());

    }

    public void writeVerifiedCertificateToAFile(X509Certificate toWrite) throws Exception {
        FileOutputStream fos = new FileOutputStream("usrCrl.crl");
        byte[] data = toWrite.getEncoded();
        fos.write(data);
    }

    public void loadStartForm() throws Exception {
        Scanner scanner = new Scanner(System.in);
        String answer;
        int tries = 3;
        boolean correct = false;

        System.out.println("Do you have an account (y/n): ");
        answer = scanner.nextLine();

        String userName, password, certName;
        if("y".equalsIgnoreCase(answer)) {

            //ENTER CERTIFICATE LOGIC NEEDED
            //IF CERTIFICATE PASSED THE TEST, THEN PROCEED TO USER NAME AND PASSWORD
            System.out.println("Input your certName: ");
            certName = scanner.nextLine();

            //SIMPLE HACKER CHECK
            FileInputStream fis = new FileInputStream(certName);
            fis.close();

            byte[] data = Files.readAllBytes(new File(certName).toPath());
            CertificateFactory factory = CertificateFactory.getInstance("X509");
            Certificate c = factory.generateCertificate(new ByteArrayInputStream(data));
            X509Certificate realCert = (X509Certificate)c;

            //IMPLEMENT LOGIC LATER ON
            /*if(!caBody.checkIfIsRevoked(realCert)) {

            }*/

            String[] credentials = CredentialsExporter.exportCredentials(realCert);
            String realUserName = credentials[0];
            String realPassword = credentials[1];

            int i = 0;
            while(i < tries) {
                System.out.println("Input your username: ");
                userName = scanner.nextLine();
                System.out.println("Input your password: ");
                password = scanner.nextLine();
                if(userName.equals(realUserName) && password.equals(realPassword)) {
                    correct = true;
                    break;
                }
                i++;
            }


            if(correct) {
                //LIST FILES ETC.
                System.out.println("YOU ARE LOGGED IN, WELCOME!");
            } else {
                caBody.addToCrlList(realCert);
                String extraInput = "";
                System.out.println("YOUR CERTIFICATE IS SUSPENDED!");
                System.out.println("Reactivate certificate (rc) or make a new registration (r)");

                switch (extraInput) {
                    case "rc":
                        System.out.println("Input your username: ");
                        userName = scanner.nextLine();
                        System.out.println("Input your password: ");
                        password = scanner.nextLine();
                        if(userName.equals(realUserName) && password.equals(realPassword)) {
                            caBody.reactivateCertificate(realCert);
                        }
                        break;
                    case "r":
                        System.out.println("WELCOME TO ACCOUNT CREATOR: ");
                        System.out.println("===========================");
                        System.out.println("Input new user name: ");
                        userName = scanner.nextLine();
                        System.out.println("Input new password: ");
                        password = scanner.nextLine();
                        PKCS10CertificationRequest req = CertificateRequestCreator.makeCertRequest();
                        caBody.signCertificate(req, userName, password);
                        break;
                    default:
                        throw new Exception("Invalid input!");
                }

            }
            //CHECK IF IT'S VALID SOMEHOW, THEN PROCEED


        } else if("n".equalsIgnoreCase(answer)) {

            System.out.println("WELCOME TO ACCOUNT CREATOR: ");
            System.out.println("===========================");
            System.out.println("Input new user name: ");
            userName = scanner.nextLine();
            System.out.println("Input new password: ");
            password = scanner.nextLine();
            PKCS10CertificationRequest req = CertificateRequestCreator.makeCertRequest();
            caBody.signCertificate(req, userName, password);
            //CREATE CERTIFICATE LOGIC NEEDED!

        } else {
            throw new Exception("Invalid input (y/n)");
        }

    }

    //TEST FUNC FROM MAIN -> GONNA IMPLEMENT IT IN CABODY CONSTRUCTOR, OR CALL THIS ONE
    public static Certificate readCertificateFromAFile() {
        try {
            byte[] data = Files.readAllBytes(new File("caCertificate.crt").toPath());
            CertificateFactory factory = CertificateFactory.getInstance("X509");
            return factory.generateCertificate(new ByteArrayInputStream(data));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

}
