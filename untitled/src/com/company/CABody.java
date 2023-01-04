package com.company;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.Scanner;
import java.util.Set;

public class CABody {

    private X509Certificate caCert;
    private X509CRL crl;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private static final int keyUsage = KeyUsage.digitalSignature | KeyUsage.keyEncipherment;
    private static final KeyPurposeId[] ekuValues = {KeyPurposeId.id_kp_serverAuth};

    public CABody() throws Exception {
        Certificate tempCert = Main.readCertificateFromAFile();
        X509Certificate realCert = (X509Certificate)tempCert;
        this.caCert = realCert;

        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (InputStream inputStream = new FileInputStream(Main.CER_FOLDER+"keystore.jks")) {
            keyStore.load(inputStream, KeyStoreCreator.KEY_STORE_PASSWORD.toCharArray());
        }
        privateKey = (PrivateKey) keyStore.getKey("CABody", "CABody".toCharArray());

        this.publicKey = caCert.getPublicKey();
        this.crl = loadCRL();
    }

    public void CABodyCreator() {
        try {
            KeyStoreCreator.generateKeyStore();

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);

            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            privateKey = keyPair.getPrivate();

            X500Name subject = new X500Name("CN=CA, O=ETF, L=BL, ST=RS, C=BA");
            X500Name issuer = subject;
            BigInteger serialNumber = BigInteger.valueOf(1);
            Date notBefore = new Date();
            long duration = 365 * 24 * 60 * 60 * 1000L; //1 year, as per project spec.
            Date notAfter = new Date(notBefore.getTime() + duration);
            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer, serialNumber,
                                                    notBefore, notAfter, subject, keyPair.getPublic());

            KeyStore keyStore = KeyStore.getInstance("JKS");
            try (InputStream inputStream = new FileInputStream(Main.CER_FOLDER+"keystore.jks")) {
                keyStore.load(inputStream, KeyStoreCreator.KEY_STORE_PASSWORD.toCharArray());
            }


            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                    .build(keyPair.getPrivate());

            caCert = new JcaX509CertificateConverter()
                    .getCertificate(certBuilder.build(contentSigner));

            keyStore.setKeyEntry("CABody", privateKey, "CABody".toCharArray(),
                    new Certificate[] {caCert});
            try (OutputStream outputStream = new FileOutputStream(Main.CER_FOLDER+"keystore.jks")) {
                keyStore.store(outputStream, KeyStoreCreator.KEY_STORE_PASSWORD.toCharArray());
            }

            byte[] caData = caCert.getEncoded();

            FileOutputStream fos = new FileOutputStream(Main.CER_FOLDER+"caCertificate.crt");
            fos.write(caData);
            fos.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public void initCrlList() throws Exception {

        X509v2CRLBuilder crlBuilder = new JcaX509v2CRLBuilder(new X500Name("CN=CA"), new Date());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(privateKey);
        X509CRL crl = new JcaX509CRLConverter().getCRL(crlBuilder.build(signer));
        byte[] data = crl.getEncoded();
        FileOutputStream fos = new FileOutputStream(Main.CER_FOLDER+"crl.crl");
        fos.write(data);

    }

    public X509CRL loadCRL() throws Exception {
        FileInputStream fis = new FileInputStream(Main.CER_FOLDER+"crl.crl");
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509CRL crl = (X509CRL) certificateFactory.generateCRL(fis);
        fis.close();

        return crl;
    }

    public void getRevokedCertificates() throws Exception {
        FileInputStream fis = new FileInputStream(Main.CER_FOLDER+"crl.crl");
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509CRL crl = (X509CRL) factory.generateCRL(fis);
        fis.close();

        Set<? extends X509CRLEntry> revokedCertificates = crl.getRevokedCertificates();

        /*if(revokedCertificates.size() == 0) {
            System.out.println("SIZE=0");
        }*/
        System.out.println("BEFOREGO");
        if(revokedCertificates != null) {
            for(X509CRLEntry entry : revokedCertificates) {
                //System.out.println("GO");
                BigInteger serialNumber = entry.getSerialNumber();
                System.out.println(serialNumber + "BLAAA");
            }
        }

    }

    public void removeFromRevokedList(X509Certificate certificate) throws Exception {
        FileInputStream fis = new FileInputStream(Main.CER_FOLDER+"crl.crl");
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509CRL crl = (X509CRL) factory.generateCRL(fis);
        fis.close();

        Set<? extends X509CRLEntry> revokedCertificates = crl.getRevokedCertificates();

        X509CRLEntry toRemove = null;
        for(X509CRLEntry entry : revokedCertificates) {
            BigInteger serialNumber = entry.getSerialNumber();
            if(serialNumber == certificate.getSerialNumber()) {
                toRemove = entry;
            }
        }

        if(toRemove != null) {
            revokedCertificates.remove(toRemove);
        }

        X500Name issuerName = new X500Name(caCert.getIssuerDN().toString());
        X509v2CRLBuilder crlBuilder = new JcaX509v2CRLBuilder(issuerName, new Date());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(privateKey);

        X509CRL crl2 = new JcaX509CRLConverter().getCRL(crlBuilder.build(signer));

        byte[] data = crl2.getEncoded();
        FileOutputStream fos = new FileOutputStream(Main.CER_FOLDER+"crl.crl");
        fos.write(data);

    }

    public boolean checkIfIsRevoked(X509Certificate certificate) throws Exception {
        Set<? extends X509CRLEntry> revokedCertificates = crl.getRevokedCertificates();
        if(revokedCertificates != null) {
            for(X509CRLEntry entry : revokedCertificates) {
                BigInteger serialNumber = entry.getSerialNumber();
                if(serialNumber.equals(certificate.getSerialNumber())) {
                    return true;
                }
            }
        }

        return false;
    }

    //IMPLEMENTATION FOR NOW -> NOT HAPPY
    public void addToCrlList(X509Certificate cert) throws Exception {
        try {
            FileInputStream fis = new FileInputStream(Main.CER_FOLDER+"crl.crl");
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509CRL crl2 = (X509CRL) factory.generateCRL(fis);
            fis.close();
            //System.out.println("SERIAL " + cert.getSerialNumber());

            X500Name issuerName = new X500Name(caCert.getIssuerDN().toString());
            X509v2CRLBuilder crlBuilder = new JcaX509v2CRLBuilder(issuerName, new Date());
            BigInteger serial = cert.getSerialNumber();
            //DON'T KNOW WHAT THIS NUMBER MEANS YET
            crlBuilder.addCRLEntry(serial, new Date(), 1);

            //SEEMS TO WORK - SO FAR SO GOOD
            if(crl2.getRevokedCertificates() != null) {
                for(X509CRLEntry entry : crl2.getRevokedCertificates()) {
                    //System.out.println("POWER RANGERS");
                    BigInteger serialNumber = entry.getSerialNumber();
                    crlBuilder.addCRLEntry(serialNumber, entry.getRevocationDate(), 1);
                }
            }


            ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(privateKey);

            X509CRL crl = new JcaX509CRLConverter().getCRL(crlBuilder.build(signer));

            byte[] data = crl.getEncoded();
            FileOutputStream fos = new FileOutputStream(Main.CER_FOLDER+"crl.crl");
            fos.write(data);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void reactivateCertificate(X509Certificate certificate) throws Exception {
        FileInputStream fis = new FileInputStream(Main.CER_FOLDER+"crl.crl");
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509CRL crl2 = (X509CRL) factory.generateCRL(fis);
        fis.close();

        if(checkIfIsRevoked(certificate)) {
            X500Name issuerName = new X500Name(caCert.getIssuerDN().toString());
            X509v2CRLBuilder crlBuilder = new JcaX509v2CRLBuilder(issuerName, new Date());
            if(crl2.getRevokedCertificates() != null) {
                for(X509CRLEntry entry : crl2.getRevokedCertificates()) {
                    //System.out.println("POWER RANGERS");
                    BigInteger serialNumber = entry.getSerialNumber();
                    if(!serialNumber.equals(certificate.getSerialNumber())) {
                        crlBuilder.addCRLEntry(serialNumber, entry.getRevocationDate(), 1);
                    }
                }
            }

            //REWRITE OLD CRL LIST
            ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(privateKey);

            X509CRL crl = new JcaX509CRLConverter().getCRL(crlBuilder.build(signer));

            byte[] data = crl.getEncoded();
            FileOutputStream fos = new FileOutputStream(Main.CER_FOLDER+"crl.crl");
            fos.write(data);

        } else {
            throw new Exception("Cannot reactivate something that's active or exists!");
        }
    }

    public X509Certificate signCertificate(PKCS10CertificationRequest certificateRequest, String uName, String pass) throws Exception {

        //PUBLIC KEY MIGHT HAVE TO BE CORRECTED, BE CAREFUL!
        /*SubjectPublicKeyInfo subjectPublicKeyInfo = certificateRequest.getSubjectPublicKeyInfo();
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded());
        PublicKey convertedKey = keyFactory.generatePublic(x509EncodedKeySpec);
        KeyPair keyPair = new KeyPair(convertedKey, null);*/

        if(checkIfCertExists(uName)) {
            throw new Exception("SORRY, BUT THAT CERTIFICATE ALREADY EXISTS!");
        }

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(4096);
        KeyPair kp = kpg.generateKeyPair();


        X500Name subject = certificateRequest.getSubject();
        Date startDate = new Date();
        //HALF A YEAR
        Date endDate = new Date(startDate.getTime() + (365/2) * 24 * 60 * 60 * 1000);

        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        X500Name issuer = new X500Name(caCert.getSubjectX500Principal().toString());
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer, serial, startDate, endDate, subject,
                kp.getPublic());

        //TEST
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        ExtendedKeyUsage eku = new ExtendedKeyUsage(ekuValues);

        //EXTENSIONS ENABLED
        /*builder.addExtension(
                Extension.extendedKeyUsage,
                false,
                eku
        );

        builder.addExtension(Extension.keyUsage, false, new KeyUsage(keyUsage));*/

        //EXTENSION NEEDED HERE
        importUNAndPassword(builder, uName, pass);

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(privateKey);
        X509Certificate signedCert = new JcaX509CertificateConverter().getCertificate(builder.build(contentSigner));

        //CREDENTIALS EXPORTED -> VERY NICE!
        String[] credentialsExported = CredentialsExporter.exportCredentials(signedCert);
        //System.out.println("STR[0]: " + credentialsExported[0]);
        /*System.out.println("STR[1]: " + credentialsExported[1]);*/

        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (InputStream inputStream = new FileInputStream(Main.CER_FOLDER+"keystore.jks")) {
            keyStore.load(inputStream, KeyStoreCreator.KEY_STORE_PASSWORD.toCharArray());
        }

        Scanner scanner = new Scanner(System.in);
        String passwordInput;
        System.out.println("Input a password for your private key (REMEMBER THIS PASSWORD): ");
        passwordInput = scanner.nextLine();

        if("".equals(passwordInput))
            throw new Exception("Invalid password");

        keyStore.setKeyEntry(credentialsExported[0], kp.getPrivate(), passwordInput.toCharArray(),
                                new Certificate[] {signedCert});

        try (OutputStream outputStream = new FileOutputStream(Main.CER_FOLDER+"keystore.jks")) {
            keyStore.store(outputStream, KeyStoreCreator.KEY_STORE_PASSWORD.toCharArray());
        }

        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128); // The AES key size in number of bits
        SecretKey secKey = generator.generateKey();
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, secKey);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.PUBLIC_KEY, kp.getPublic());
        byte[] encryptedKey = cipher.doFinal(secKey.getEncoded());
        Files.write(Paths.get(Main.keyPath+"/"+credentialsExported[0]), encryptedKey);

        byte[] data = signedCert.getEncoded();

        System.out.println("SAVING CERTIFICATE WITH THE NAME OF YOUR USER NAME!");

        FileOutputStream fos = new FileOutputStream(Main.CER_FOLDER+uName + ".crt");
        fos.write(data);
        fos.close();

        return  signedCert;

    }

    private boolean checkIfCertExists(String certName) {
        boolean exists = false;

        File file = new File(Main.CER_FOLDER);
        File[] files = file.listFiles();
        for(File f : files) {
            if(f.getName().equalsIgnoreCase(certName+".crt")) {
                exists = true;
            }
        }

        return exists;
    }

    private void importUNAndPassword(X509v3CertificateBuilder builder, String userName, String password) throws Exception {

        String toConvert = userName + ":" + password;
        ASN1UTF8String utf8String = new DERUTF8String(toConvert);
        byte[] str = utf8String.getEncoded();
        ASN1Primitive asn1String = ASN1Primitive.fromByteArray(str);

        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier("1.2.3.4.5.6.7.8.9");
        DERSequence seq = new DERSequence(new ASN1Encodable[] { oid, asn1String});

        ArrayList<GeneralName> namesList = new ArrayList<>();
        namesList.add(new GeneralName(GeneralName.otherName, seq));
        GeneralNames subjectAltNames = GeneralNames.getInstance(new DERSequence((GeneralName[]) namesList.toArray(new GeneralName[] {})));
        builder.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);

        new CredentialsExporter(oid);
        //System.out.println("BLAA");
    }

    public X509Certificate getCaCert() {
        return caCert;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
}
