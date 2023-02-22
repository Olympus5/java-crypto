package fr.olympus5.learning;

import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Set;

class JcaTest {
    private static final char[] HEX_DIGIT = "0123456789ABCDEF".toCharArray();

    public static String bytesToHex(final byte[] bytes) {
        final char[] hex = new char[bytes.length * 2];
        for (int i = 0, c = bytes.length; i < c; i++) {
            hex[i * 2] = HEX_DIGIT[(bytes[i] >>> 4) & 0x0F];
            hex[i * 2 + 1] = HEX_DIGIT[bytes[i] & 0x0F];
        }
        return new String(hex);
    }

    @Test
    void listProviders() {
        final Provider[] providers = Security.getProviders();

        Arrays.asList(providers).forEach(p -> System.out.println("Provider: " + p.getName() + ", version: " + p.getVersion()));
    }

    @Test
    void listServicesFromSunJCE() {
        final Provider provider = Security.getProvider("SunJCE");
        final Set<Provider.Service> services = provider.getServices();

        System.out.println("Services du provider " + provider.getName());
        services.forEach(s -> System.out.println("\t" + s.getType() + " " + s.getAlgorithm()));
    }

    @Test
    void listAvailableAlgorithmsForAGivenType() {
        Security.getAlgorithms("Cipher").forEach(System.out::println);
    }

    @Test
    void newMessageDigestInstance() throws NoSuchAlgorithmException {
        MessageDigest.getInstance("SHA-1");
        MessageDigest.getInstance("sha-1");
    }

    @Test
    void messageDigest() throws NoSuchAlgorithmException {
        final String message = "Hello world!";
        hash("MD5", message);
        hash("MD2", message);
        hash("SHA-1", message);
        hash("SHA-256", message);
        hash("SHA-512", message);
    }

    private static void hash(final String hashAlgorithm, final String message) throws NoSuchAlgorithmException {
        final MessageDigest md5 = MessageDigest.getInstance(hashAlgorithm);
        md5.update(message.getBytes());
        final byte[] digest = md5.digest();

        System.out.println("Algorithme: " + hashAlgorithm);
        System.out.println(bytesToHex(digest));
    }
}
