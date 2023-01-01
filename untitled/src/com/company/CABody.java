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
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
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

        FileInputStream fis = new FileInputStream("private_key.pem");
        byte[] key = fis.readAllBytes();
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        this.privateKey = keyFactory.generatePrivate(keySpec);
        /*byte[] encodedKey = realCert.getEncoded();
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        this.privateKey = privateKey;*/

        this.publicKey = caCert.getPublicKey();
        this.crl = loadCRL();
        //System.out.println(crl.getSigAlgName());

        //LOGIC TO LOAD CERT FROM FILW
    }

    public void CABodyCreator() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);

            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            privateKey = keyPair.getPrivate();

            FileOutputStream stream = new FileOutputStream("private_key.pem");
            stream.write(privateKey.getEncoded());
            stream.close();

            X500Name subject = new X500Name("CN=CA, O=ETF, L=BL, ST=RS, C=BA");

            X500Name issuer = subject;

            BigInteger serialNumber = BigInteger.valueOf(1);

            Date notBefore = new Date();
            long duration = 365 * 24 * 60 * 60 * 1000L; //1 year, as per project spec.
            Date notAfter = new Date(notBefore.getTime() + duration);

            //SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer, serialNumber,
                                                    notBefore, notAfter, subject, keyPair.getPublic());

            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                    .build(keyPair.getPrivate());

            caCert = new JcaX509CertificateConverter()
                    .getCertificate(certBuilder.build(contentSigner));

            //Seems that method doesn't exist
            //caCert.writeTo(new FileOutputStream("ca.crt"));

            byte[] caData = caCert.getEncoded();

            FileOutputStream fos = new FileOutputStream("caCertificate.crt");
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
        FileOutputStream fos = new FileOutputStream("crl.crl");
        fos.write(data);

    }

    public X509CRL loadCRL() throws Exception {
        FileInputStream fis = new FileInputStream("crl.crl");
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509CRL crl = (X509CRL) certificateFactory.generateCRL(fis);
        fis.close();

        return crl;
    }

    public void getRevokedCertificates() throws Exception {
        FileInputStream fis = new FileInputStream("crl.crl");
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
        FileInputStream fis = new FileInputStream("crl.crl");
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
        FileOutputStream fos = new FileOutputStream("crl.crl");
        fos.write(data);

    }

    public boolean checkIfIsRevoked(X509Certificate certificate) throws Exception {
        Set<? extends X509CRLEntry> revokedCertificates = crl.getRevokedCertificates();
        for(X509CRLEntry entry : revokedCertificates) {
            BigInteger serialNumber = entry.getSerialNumber();
            if(serialNumber.equals(certificate.getSerialNumber())) {
                return true;
            }
        }
        return false;
    }

    //IMPLEMENTATION FOR NOW -> NOT HAPPY
    public void addToCrlList(X509Certificate cert) throws Exception {
        try {
            FileInputStream fis = new FileInputStream("crl.crl");
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
            for(X509CRLEntry entry : crl2.getRevokedCertificates()) {
                //System.out.println("POWER RANGERS");
                BigInteger serialNumber = entry.getSerialNumber();
                crlBuilder.addCRLEntry(serialNumber, entry.getRevocationDate(), 1);
            }

            ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(privateKey);

            X509CRL crl = new JcaX509CRLConverter().getCRL(crlBuilder.build(signer));

            byte[] data = crl.getEncoded();
            FileOutputStream fos = new FileOutputStream("crl.crl");
            fos.write(data);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void reactivateCertificate(X509Certificate certificate) throws Exception {
        FileInputStream fis = new FileInputStream("crl.crl");
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509CRL crl2 = (X509CRL) factory.generateCRL(fis);
        fis.close();

        if(checkIfIsRevoked(certificate)) {
            X500Name issuerName = new X500Name(caCert.getIssuerDN().toString());
            X509v2CRLBuilder crlBuilder = new JcaX509v2CRLBuilder(issuerName, new Date());
            for(X509CRLEntry entry : crl2.getRevokedCertificates()) {
                //System.out.println("POWER RANGERS");
                BigInteger serialNumber = entry.getSerialNumber();
                if(!serialNumber.equals(certificate.getSerialNumber())) {
                    crlBuilder.addCRLEntry(serialNumber, entry.getRevocationDate(), 1);
                }
            }

            //REWRITE OLD CRL LIST
            ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(privateKey);

            X509CRL crl = new JcaX509CRLConverter().getCRL(crlBuilder.build(signer));

            byte[] data = crl.getEncoded();
            FileOutputStream fos = new FileOutputStream("crl.crl");
            fos.write(data);

        } else {
            throw new Exception("Cannot reactivate something that's active or exists!");
        }
    }

    public X509Certificate signCertificate(PKCS10CertificationRequest certificateRequest, String uName, String pass) throws Exception {

        SubjectPublicKeyInfo subjectPublicKeyInfo = certificateRequest.getSubjectPublicKeyInfo();

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded());
        PublicKey convertedKey = keyFactory.generatePublic(x509EncodedKeySpec);

        KeyPair keyPair = new KeyPair(convertedKey, null);

        X500Name subject = certificateRequest.getSubject();
        Date startDate = new Date();
        Date endDate = new Date(startDate.getTime() + (365/2) * 24 * 60 * 60 * 1000);

        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        //System.out.println("SERIAL " + serial);


        /*X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer, serialNumber,
                notBefore, notAfter, subject, keyPair.getPublic());*/
        X500Name issuer = new X500Name(caCert.getSubjectX500Principal().toString());
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer, serial, startDate, endDate, subject,
                keyPair.getPublic());

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
        /*String[] credentialsExported = CredentialsExporter.exportCredentials(signedCert);
        System.out.println("STR[0]: " + credentialsExported[0]);
        System.out.println("STR[1]: " + credentialsExported[1]);*/

        byte[] data = signedCert.getEncoded();

        FileOutputStream fos = new FileOutputStream(uName + ".crt");
        fos.write(data);
        fos.close();


        return  signedCert;

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
