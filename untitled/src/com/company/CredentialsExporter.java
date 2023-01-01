package com.company;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import java.security.cert.X509Certificate;

public class CredentialsExporter {

    private static ASN1ObjectIdentifier oid;

    public CredentialsExporter(ASN1ObjectIdentifier oid) {
        this.oid = oid;
    }

    public static String[] exportCredentials(X509Certificate cert) throws Exception {
        String[] exported = new String[2];

        byte[] v = cert.getExtensionValue(Extension.subjectAlternativeName.getId());
        GeneralNames gn = GeneralNames.getInstance(org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils.parseExtensionValue(v));
        GeneralName[] names = gn.getNames();
        for (GeneralName name : names) {
            if (name.getTagNo() == GeneralName.otherName) {
                ASN1Sequence seq = ASN1Sequence.getInstance(name.getName());
                //if ("1.2.3.4.5.6.7.8.9".equals(oid.getId())) {
                    ASN1Primitive asn1Primitive = (ASN1Primitive) seq.getObjectAt(1);
                    String str = asn1Primitive.toString();
                    exported = str.split(":");
                //}
            }
        }

        return exported;
    }

}
