package fr.olympus5.learning;

import fr.olympus5.helper.ConverterHelper;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.PBEKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

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

    @Test
    void keySpecToSecretKey() throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        final KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        byte[] secretKeyBytes = keyGenerator.generateKey().getEncoded();
        final KeySpec secretKeySpec = new DESKeySpec(secretKeyBytes);
        final SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
        final SecretKey secretKey = secretKeyFactory.generateSecret(secretKeySpec);

        System.out.printf("cle(%s,%s): %s%n",
                secretKey.getAlgorithm(),
                secretKey.getFormat(),
                ConverterHelper.bytesToHex(secretKey.getEncoded()));
    }

    @Test
    void secretKeyToKeySpec() throws NoSuchAlgorithmException, InvalidKeySpecException {
        final KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
        keyGenerator.init(168, SecureRandom.getInstance("SHA1PRNG"));
        final SecretKey secretKey = keyGenerator.generateKey();
        final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");

        final DESedeKeySpec keySpec = (DESedeKeySpec) keyFactory.getKeySpec(secretKey, DESedeKeySpec.class);
        System.out.println(ConverterHelper.bytesToHex(keySpec.getKey()));
    }
}
