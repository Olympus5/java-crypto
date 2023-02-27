package fr.olympus5.learning;

import fr.olympus5.helper.ConverterHelper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

class JceTest {
    private static final FileSystem FILE_SYSTEM = FileSystems.getDefault();
    private static final String DECRYPTED_FILE_NAME = "jce.txt";
    private static final String ENCRYPTED_FILE_NAME = "jce.enc";

    private Path decryptedFile;
    private Path encryptedFile;

    @BeforeEach
    void setUp() throws IOException {
        decryptedFile = Files.createFile(FILE_SYSTEM.getPath(DECRYPTED_FILE_NAME));
        Files.write(decryptedFile, "Hello World!".getBytes());
        encryptedFile = Files.createFile(FILE_SYSTEM.getPath(ENCRYPTED_FILE_NAME));
    }

    @AfterEach
    void tearDown() throws IOException {
        Files.delete(decryptedFile);
        Files.delete(encryptedFile);
    }

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

    @Test
    void cipherInstance() throws NoSuchPaddingException, NoSuchAlgorithmException {
        // transformation = algorithm/mode/padding or algorithm (with default mode and padding)
        final Cipher cipher = Cipher.getInstance("DES/CBC/NoPadding");
        final Cipher cipher2 = Cipher.getInstance("AES");
    }

    @Test
    void cipher() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        final KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        keyGenerator.init(56);
        final SecretKey secretKey = keyGenerator.generateKey();
        System.out.printf("cle(%s,%s): %s%n",
                secretKey.getAlgorithm(),
                secretKey.getFormat(),
                ConverterHelper.bytesToHex(secretKey.getEncoded()));

        final Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        final byte[] encryptedMessage = cipher.doFinal("Hello world!".getBytes(StandardCharsets.US_ASCII));
        System.out.println("encrypted text: " + ConverterHelper.bytesToHex(encryptedMessage));

        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        final byte[] decryptedMessage = cipher.doFinal(encryptedMessage);
        System.out.println("decrypted text: " + new String(decryptedMessage, StandardCharsets.US_ASCII));
    }

    @Test
    void cipherKey() throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, InvalidKeyException {
        final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        final SecretKey secretKey = keyGenerator.generateKey();
        System.out.println("key: " + ConverterHelper.bytesToHex(secretKey.getEncoded()));

        keyGenerator.init(128);
        final SecretKey encryptionKey = keyGenerator.generateKey();
        final Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.WRAP_MODE, encryptionKey);
        final byte[] encryptedKeyBytes = cipher.wrap(secretKey);
        System.out.println("encrypted key: " + ConverterHelper.bytesToHex(encryptedKeyBytes));

        cipher.init(Cipher.UNWRAP_MODE, encryptionKey);
        final Key decryptedKey = cipher.unwrap(encryptedKeyBytes, "AES", Cipher.SECRET_KEY);
        System.out.println("decrypted key: " + ConverterHelper.bytesToHex(decryptedKey.getEncoded()));
    }

    @Test
    void keyAlgorithmParameterSpec() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
        final String transformation = "PBEWithMD5AndDES";
        final SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(transformation);
        final PBEKeySpec keySpec = new PBEKeySpec("pass".toCharArray());
        final SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
        final PBEParameterSpec algorithmParameterSpec = new PBEParameterSpec(
                new SecureRandom().generateSeed(8), 1000);

        final Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, algorithmParameterSpec);
        final byte[] encryptedTextBytes = cipher.doFinal("Hello world!".getBytes());
        System.out.println("encrypted text: " + ConverterHelper.bytesToHex(encryptedTextBytes));

        final AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance(transformation);
        algorithmParameters.init(cipher.getParameters().getEncoded());
        cipher.init(Cipher.DECRYPT_MODE, secretKey, algorithmParameters);
        System.out.println("decrypted text: " + new String(cipher.doFinal(encryptedTextBytes)));
    }

    @Test
    void desCipher() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        final KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        final SecretKey secretKey = keyGenerator.generateKey();
        String messageToEncrypt = "Hello World!";

        encryptDecrypt(secretKey, "DES", messageToEncrypt);
        encryptDecrypt(secretKey, "DES/ECB/PKCS5Padding", messageToEncrypt);
        encryptDecrypt(secretKey, "DES/CBC/PKCS5Padding", messageToEncrypt);
        encryptDecrypt(secretKey, "DES/PCBC/PKCS5Padding", messageToEncrypt);
        encryptDecrypt(secretKey, "DES/CFB/PKCS5Padding", messageToEncrypt);
        encryptDecrypt(secretKey, "DES/OFB/PKCS5Padding", messageToEncrypt);
    }

    @Test
    void aesCipher() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256, SecureRandom.getInstance("SHA1PRNG"));
        final SecretKey secretKey = keyGenerator.generateKey();

        encryptDecrypt(secretKey, "AES", "Hello World!");
    }

    private static void encryptDecrypt(final SecretKey secretKey, final String transformation, final String messageToEncrypt) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        final Cipher desCipher = Cipher.getInstance(transformation);
        desCipher.init(Cipher.ENCRYPT_MODE, secretKey);
        final byte[] encryptedTextBytes = desCipher.doFinal(messageToEncrypt.getBytes());
        System.out.println(ConverterHelper.bytesToHex(encryptedTextBytes));

        final Cipher desDecipher = Cipher.getInstance(transformation);
        desDecipher.init(Cipher.DECRYPT_MODE, secretKey, desCipher.getParameters());
        final byte[] decryptedTextBytes = desDecipher.doFinal(encryptedTextBytes);
        System.out.println(new String(decryptedTextBytes));
    }

    @Test
    void cipherInputStream() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        final KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        keyGenerator.init(56, new SecureRandom());
        final SecretKey secretKey = keyGenerator.generateKey();
        final Cipher cipher = Cipher.getInstance("DES");

        System.out.println("original file: " + new String(Files.readAllBytes(decryptedFile)));

        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        try (final InputStream is = Files.newInputStream(decryptedFile);
             final CipherInputStream cis = new CipherInputStream(is, cipher)) {
            final byte[] encryptedTextBytes = cis.readAllBytes();
            Files.write(encryptedFile, encryptedTextBytes);
        }

        System.out.println("encrypted file: " + ConverterHelper.bytesToHex(Files.readAllBytes(encryptedFile)));

        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        try (final InputStream is = Files.newInputStream(encryptedFile);
             final CipherInputStream cis = new CipherInputStream(is, cipher)) {
            final byte[] decryptedTextBytes = cis.readAllBytes();
            System.out.println("decrypted content: " + new String(decryptedTextBytes));
        }
    }

    @Test
    void cipherBlockOutputStream() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, InvalidAlgorithmParameterException {
        final byte[] textToEncryptBytes = "Hello World! This is the text to encrypt! It's fucking Awesome! Have a nice day :)".getBytes();
        final Cipher cipher = Cipher.getInstance("DES/CFB8/PKCS5Padding");
        final KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        keyGenerator.init(56);
        final SecretKey secretKey = keyGenerator.generateKey();

        System.out.println("original text: " + new String(textToEncryptBytes));

        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        OutputStream os;
        CipherOutputStream cos = null;
        try {
            os = Files.newOutputStream(encryptedFile);
            cos = new CipherOutputStream(os, cipher);
            for(int i = 0, blockSize = cipher.getBlockSize(); i < textToEncryptBytes.length; i += blockSize) {
                cos.write(textToEncryptBytes, i, getNumberOfBytesToWrite(textToEncryptBytes, blockSize, i));
                // flush encrypted block by encrypted block
                cos.flush();
            }
        } finally {
            // close() call the Cipher doFinal() method and the OutputStream flush() and close() methods
            cos.close();
        }

        byte[] encryptedFileBytes = Files.readAllBytes(encryptedFile);
        System.out.println("encrypted file: " + ConverterHelper.bytesToHex(encryptedFileBytes));

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(cipher.getIV()));
        try {
            os = Files.newOutputStream(decryptedFile);
            cos = new CipherOutputStream(os, cipher);
            for(int i = 0, blockSize = cipher.getBlockSize(); i < encryptedFileBytes.length; i += blockSize) {
                cos.write(encryptedFileBytes, i, getNumberOfBytesToWrite(encryptedFileBytes, blockSize, i));
                cos.flush();
            }
        } finally {
            cos.close();
        }

        System.out.println("decrypted file: " + new String(Files.readAllBytes(decryptedFile)));
    }

    private static int getNumberOfBytesToWrite(byte[] textToEncryptBytes, int blockSize, int i) {
        return (i + blockSize < textToEncryptBytes.length) ? i + blockSize - i : textToEncryptBytes.length - i;
    }

}
