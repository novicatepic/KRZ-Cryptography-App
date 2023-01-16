package com.company;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class CertificateRequestCreator {

    private static int id = 0;

    public CertificateRequestCreator() {}

    //Simple request generator
    public static PKCS10CertificationRequest makeCertRequest() {
        id++;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            String cn = "CN=Req"+String.valueOf(id);
            X500Name subject = new X500Name(cn+", O=ETF, L=BL, ST=RS, C=BA");
            PKCS10CertificationRequestBuilder cerBuilder = new JcaPKCS10CertificationRequestBuilder(
                    subject, keyPair.getPublic()
            );

            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
            PKCS10CertificationRequest request = cerBuilder.build(contentSigner);

            return request;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

}
