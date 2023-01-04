package com.company;

import java.io.FileOutputStream;
import java.security.KeyStore;

public class KeyStoreCreator {

    public static final String KEY_STORE_PASSWORD = "password";

    public KeyStoreCreator() {}

    public static void generateKeyStore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);

        FileOutputStream fos = new FileOutputStream(Main.CER_FOLDER+"keystore.jks");
        keyStore.store(fos, KEY_STORE_PASSWORD.toCharArray());
        fos.close();
    }

}
