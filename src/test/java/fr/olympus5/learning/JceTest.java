package fr.olympus5.learning;

import fr.olympus5.helper.ConverterHelper;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

class JceTest {
    @Test
    void keyGeneratorWithKeySize() throws NoSuchAlgorithmException {
        final KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
        keyGenerator.init(168);
        final SecretKey secretKey = keyGenerator.generateKey();
        System.out.printf("cle(%s,%s): %s%n",
                secretKey.getAlgorithm(),
                secretKey.getFormat(),
                ConverterHelper.bytesToHex(secretKey.getEncoded()));
    }

    @Test
    void keyGeneratorWithSecureRandom() throws NoSuchAlgorithmException {
        final KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
        final SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        keyGenerator.init(secureRandom);
        final SecretKey secretKey = keyGenerator.generateKey();
        System.out.printf("cle(%s,%s): %s%n",
                secretKey.getAlgorithm(),
                secretKey.getFormat(),
                ConverterHelper.bytesToHex(secretKey.getEncoded()));
    }

    @Test
    void keyGeneratorWithKeySizeAndSecureRandom() throws NoSuchAlgorithmException {
        final KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        keyGenerator.init(56, new SecureRandom());
        final SecretKey secretKey = keyGenerator.generateKey();
        System.out.printf("cle(%s,%s): %s%n",
                secretKey.getAlgorithm(),
                secretKey.getFormat(),
                ConverterHelper.bytesToHex(secretKey.getEncoded()));
    }

    @Test
    void keyGenerator() throws NoSuchAlgorithmException {
        final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        final SecretKey secretKey = keyGenerator.generateKey();
        System.out.printf("cle(%s,%s): %s%n",
                secretKey.getAlgorithm(),
                secretKey.getFormat(),
                ConverterHelper.bytesToHex(secretKey.getEncoded()));
    }
}
