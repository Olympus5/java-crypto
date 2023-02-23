package fr.olympus5.learning;

import fr.olympus5.helper.ConverterHelper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.fail;

class JcaTest {
    private static final String OUTPUT_FILE_NAME = "jca.out";
    private static final String INPUT_FILE_NAME = "jca.in";
    private static final String KEY_STORE_NAME = "keystore.store";
    private static final FileSystem FILE_SYSTEM = FileSystems.getDefault();

    private Path outputFile;
    private Path inputFile;
    private Path keyStoreFile;

    @BeforeEach
    void setUp() throws IOException {
        outputFile = Files.createFile(FILE_SYSTEM.getPath(OUTPUT_FILE_NAME));
        inputFile = Files.createFile(FILE_SYSTEM.getPath(INPUT_FILE_NAME));
        keyStoreFile = Files.createFile(FILE_SYSTEM.getPath(KEY_STORE_NAME));
    }

    @AfterEach
    void tearDown() throws IOException {
        Files.delete(outputFile);
        Files.delete(inputFile);
        Files.delete(keyStoreFile);
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

    private void hash(final String hashAlgorithm, final String message) throws NoSuchAlgorithmException {
        final MessageDigest md5 = MessageDigest.getInstance(hashAlgorithm);
        md5.update(message.getBytes());
        final byte[] digest = md5.digest();

        System.out.println("Algorithme: " + hashAlgorithm);
        System.out.println(ConverterHelper.bytesToHex(digest));
    }

    @Test
    void outputStreamDigest() throws IOException, NoSuchAlgorithmException {
        final byte[] data = "Hello world!".getBytes();
        final MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
        try (final OutputStream os = Files.newOutputStream(outputFile);
             final DigestOutputStream dos = new DigestOutputStream(os, messageDigest)) {
            dos.write(data);

            System.out.println(new String(Files.readAllBytes(outputFile)));
            System.out.println(ConverterHelper.bytesToHex(dos.getMessageDigest().digest()));
        }
    }

    @Test
    void inputStreamDigest() throws IOException, NoSuchAlgorithmException {
        Files.write(inputFile, Collections.singletonList("Hello world!"), StandardCharsets.UTF_8);
        final MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
        try (final InputStream is = Files.newInputStream(inputFile);
             final DigestInputStream dis = new DigestInputStream(is, messageDigest);) {
            final byte[] buffer = new byte[64];
            final StringBuilder stringBuilder = new StringBuilder();

            while (dis.read(buffer) != -1) {
                stringBuilder.append(StandardCharsets.UTF_8.decode(ByteBuffer.wrap(buffer)).array());
            }

            System.out.println(stringBuilder);
            System.out.println(ConverterHelper.bytesToHex(dis.getMessageDigest().digest()));
        }
    }

    @Test
    void dataSignature() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024, new SecureRandom());
        final KeyPair keyPair = keyPairGenerator.generateKeyPair();
        final Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate(), new SecureRandom());
        signature.update("Hello world!".getBytes());

        final byte[] signatureBytes = signature.sign();
        System.out.println(ConverterHelper.bytesToHex(signatureBytes));

        signature.initVerify(keyPair.getPublic());
        signature.update("Hello world!".getBytes());
        System.out.println("Résultat signature: " + signature.verify(signatureBytes));
    }

    @Test
    void storeCertificate() {
        fail();
    }

    @Test
    void storeKey() {
        fail();
    }

    @Test
    void keyGenerator() throws NoSuchAlgorithmException {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(1024, new SecureRandom());
        final KeyPair keyPair = keyPairGenerator.generateKeyPair();
        final PrivateKey privateKey = keyPair.getPrivate();
        System.out.println(privateKey);
        final PublicKey publicKey = keyPair.getPublic();
        System.out.println(publicKey);
    }

    @Test
    void keyGeneratorWithCustomSecureRandom() throws NoSuchAlgorithmException, NoSuchProviderException {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        final SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG", "SUN");
        secureRandom.setSeed(new byte[256]);
        keyPairGenerator.initialize(1024, secureRandom);
        final KeyPair keyPair = keyPairGenerator.generateKeyPair();
        final PrivateKey privateKey = keyPair.getPrivate();
        System.out.println(privateKey);
        final PublicKey publicKey = keyPair.getPublic();
        System.out.println(publicKey);
    }
}
