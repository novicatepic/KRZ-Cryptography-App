package com.company;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
//import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;


import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

public class Main {

    KeyPair keyPair;
    static X509Certificate caCertificate;


    public Main() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        this.keyPair = keyPairGenerator.generateKeyPair();

        Date startDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 100);
        Date endTime = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000);

        BigInteger serialNumber = new BigInteger(64, new SecureRandom());
        X500Name subject = new X500Name("CN=My CA");
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(this.keyPair.getPublic().getEncoded());
        //PublicKey

        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(subject,
                serialNumber, startDate, endTime, subject, this.keyPair.getPublic());

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .build(this.keyPair.getPrivate());

        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(contentSigner));

        this.caCertificate = certificate;

    }


    public static void main(String[] args) throws Exception {
	    Main main = new Main();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        Certificate createdCert = main.createCertificate(keyPair, "Novica");
        System.out.println(caCertificate.getSerialNumber());
        System.out.println(caCertificate.getIssuerDN());

        System.out.println(createdCert.getPublicKey());
    }


    public KeyPair getCAKeyPair() {
        return this.keyPair;
    }

    public X509Certificate getCaCertificate() {
        return this.caCertificate;
    }

    public Certificate createCertificate(KeyPair keyPair, String subject) throws Exception {
        Date startDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 100);
        Date endTime = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000);

        BigInteger serialNumber = new BigInteger(64, new SecureRandom());
        X500Name subjectName = new X500Name("CN="+subject);
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(subjectName,
                serialNumber, startDate, endTime, subjectName, this.keyPair.getPublic());

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .build(this.keyPair.getPrivate());

        X509Certificate certificate =  new JcaX509CertificateConverter().getCertificate(
                certificateBuilder.build(contentSigner)
        );

        return certificate;

    }
}
