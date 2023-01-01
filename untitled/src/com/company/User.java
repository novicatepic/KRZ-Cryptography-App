package com.company;

import java.util.Random;

public class User {

    private String userName;
    private String password;

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
    public void uploadDocument(String document) {
        Random random = new Random();

        int documentParts = random.nextInt() + Main.MIN_PARTS_OF_DOCUMENT;

        //String[] partedDocument = document.
    }

    public String readDocument() {
        return null;
    }


}
