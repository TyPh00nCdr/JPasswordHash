package de.uni_hamburg.informatik.svs.passwordhash;

import com.google.common.base.Charsets;
import com.google.common.io.BaseEncoding;
import com.google.common.io.Files;
import com.google.common.primitives.Ints;
import org.apache.commons.cli.*;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.File;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class Useradmin implements Useradministration {

    private static final String ADD_USER_OPTION = "addUser";
    private static final String CHECK_USER_OPTION = "checkUser";
    private static final int HASH_ITERATIONS = 2 * Short.MAX_VALUE;
    private static final File FILE = new File("passwords.txt");

    public static void main(String[] args) {
        createJPasswordHasher(args);
    }

    private Options options;

    private Useradmin() {
        this.options = new Options();
        OptionGroup mutex = new OptionGroup();
        Option addUser = Option.builder(ADD_USER_OPTION)
                .hasArg()
                .argName("BENUTZERNAME")
                .desc("fügt einen neuen Benutzer hinzu")
                .build();
        Option checkUser = Option.builder(CHECK_USER_OPTION)
                .hasArg()
                .argName("BENUTZERNAME")
                .desc("überprüft das Passwort für einen existierenden Benutzer")
                .build();
        mutex.addOption(addUser);
        mutex.addOption(checkUser);
        mutex.setRequired(true);
        options.addOptionGroup(mutex);
    }

    @Override
    public void addUser(String username, char[] password) {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[20];
        random.nextBytes(salt);

        try {
            String line = username + "$" + HASH_ITERATIONS + "$" + BaseEncoding.base64().encode(salt) + "$"
                    + BaseEncoding.base64().encode(createHash(salt, password, HASH_ITERATIONS)) + '\n';

            Files.append(line, FILE, Charsets.UTF_8);
        } catch (IOException e) {
            System.err.println("Passwort-Datei konnte nicht gelesen werden.");
        }
    }

    private void addUser(String username) {
        if (getEntryFor(username) == null) {
            char[] firstAtt;
            char[] secondAtt;

            do {
                firstAtt = System.console().readPassword("Gewünschtes Passwort eingeben: ");
                secondAtt = System.console().readPassword("Gewünschtes Passwort wiederholen: ");
            } while (!Arrays.equals(firstAtt, secondAtt));

            Arrays.fill(secondAtt, ' ');
            addUser(username, firstAtt);
            Arrays.fill(firstAtt, ' ');
        } else {
            System.err.println("Benutzer '" + username + "' bereits vorhanden.");
        }
    }

    @Override
    public boolean checkUser(String username, char[] password) {
        String[] entry = getEntryFor(username);
        int iterations = Ints.tryParse(entry[1]);
        byte[] salt = BaseEncoding.base64().decode(entry[2]);
        byte[] hash = createHash(salt, password, iterations);

        return MessageDigest.isEqual(hash, BaseEncoding.base64().decode(entry[3]));
    }

    private void checkUser(String username) {
        if (getEntryFor(username) != null) {
            char[] passwd = System.console().readPassword("Passwort eingeben: ");
            if (checkUser(username, passwd)) {
                System.out.println("Passwort korrekt für Benutzer '" + username + "'");
            } else {
                System.out.println("Passwort inkorrekt.");
            }
            Arrays.fill(passwd, ' ');
        } else {
            System.err.println("Kein Benutzer '" + username + "' vorhanden.");
        }
    }

    private byte[] createHash(byte[] salt, char[] password, int iterations) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, 160);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            System.err.println("Fehler beim Hashing. Bitte verwenden Sie eine aktuelle Java-Version.\n" + ex.getMessage());
            return new byte[]{};
        }
    }

    private String[] getEntryFor(String username) {
        try {
            for (String line : Files.readLines(FILE, Charsets.UTF_8)) {
                String[] split = line.split("\\$");
                if (split[0].equals(username) && split.length == 4) {
                    return split;
                }
            }
        } catch (Exception e) {
            System.err.println("Password-Datei in keinem zulässigen Format.");
        }

        return null;
    }

    private void withArguments(String[] cmdArgs) {
        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();

        try {
            CommandLine cmd = parser.parse(this.options, cmdArgs, true);

            for (Option option : cmd.getOptions()) {
                switch (option.getOpt()) {
                    case ADD_USER_OPTION:
                        options.getOptionGroup(option).setSelected(option);
                        addUser(option.getValue());
                        break;
                    case CHECK_USER_OPTION:
                        options.getOptionGroup(option).setSelected(option);
                        checkUser(option.getValue());
                        break;
                }
            }

        } catch (ParseException e) {
            formatter.printHelp(this.getClass().getSimpleName(), null, this.options, null, true);
        }
    }

    private static void createJPasswordHasher(String[] cmdArgs) {
        new Useradmin().withArguments(cmdArgs);
    }
}
