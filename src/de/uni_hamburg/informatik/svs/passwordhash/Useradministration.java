package de.uni_hamburg.informatik.svs.passwordhash;


public interface Useradministration {

    void addUser(String username, char[] password);

    boolean checkUser(String username, char[] password);
}
