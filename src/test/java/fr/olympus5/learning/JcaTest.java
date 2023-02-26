package fr.olympus5.learning;

import fr.olympus5.helper.ConverterHelper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.*;
import java.util.*;

import static org.junit.jupiter.api.Assertions.fail;

class JcaTest {
    private static final String OUTPUT_FILE_NAME = "jca.out";
    private static final String INPUT_FILE_NAME = "jca.in";
    private static final String KEY_STORE_NAME = "store.p12";
    private static final String CERTIFICATE_NAME = "jca.crt";
    private static final FileSystem FILE_SYSTEM = FileSystems.getDefault();
    private static final String PKCS8_KEY_NAME = "rsa.pkcs8";

    private Path outputFile;
    private Path inputFile;
    private Path keyStoreFile;
    private Path certificateFile;
    private Path privateKeyFile;

    @BeforeEach
    void setUp() throws IOException, URISyntaxException {
        outputFile = Files.createFile(FILE_SYSTEM.getPath(OUTPUT_FILE_NAME));
        inputFile = Files.createFile(FILE_SYSTEM.getPath(INPUT_FILE_NAME));
        final URI keyStoreUri = Thread.currentThread().getContextClassLoader().getResource(KEY_STORE_NAME).toURI();
        keyStoreFile = FILE_SYSTEM.provider().getPath(keyStoreUri);
        final URI certificateUri = Thread.currentThread().getContextClassLoader().getResource(CERTIFICATE_NAME).toURI();
        certificateFile = FILE_SYSTEM.provider().getPath(certificateUri);
        final URI privateKeyUri = Thread.currentThread().getContextClassLoader().getResource(PKCS8_KEY_NAME).toURI();
        privateKeyFile = FILE_SYSTEM.provider().getPath(privateKeyUri);
    }

    @AfterEach
    void tearDown() throws IOException {
        Files.delete(outputFile);
        Files.delete(inputFile);
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
    void loadCertificate() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        try(final InputStream is = Files.newInputStream(keyStoreFile)) {
            keyStore.load(is, "changeit".toCharArray());
            final String alias = "mycert";
            final Certificate certificate = keyStore.getCertificate(alias);

            System.out.println(certificate);
        }
    }

    @Test
    void loadKey() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        try(final InputStream is = Files.newInputStream(keyStoreFile)) {
            keyStore.load(is, "changeit".toCharArray());
            final String alias = "mycert";
            final Key key = keyStore.getKey(alias, "changeit".toCharArray());

            if(key instanceof PrivateKey) {
                final Certificate certificate = keyStore.getCertificate(alias);
                final PublicKey publicKey = certificate.getPublicKey();
                final PrivateKey privateKey = (PrivateKey) key;
                final KeyPair keyPair = new KeyPair(publicKey, privateKey);

                System.out.println("public key: " + ConverterHelper.bytesToHex(keyPair.getPublic().getEncoded()));
                System.out.println("private key: " + ConverterHelper.bytesToHex(keyPair.getPrivate().getEncoded()));
            } else {
                System.out.println("secret key (public key): " + ConverterHelper.bytesToHex(key.getEncoded()));
            }
        }
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

    @Test
    void keySpecToPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        final PublicKey publicKey = keyPairGenerator.generateKeyPair().getPublic();

        System.out.println(ConverterHelper.bytesToHex(publicKey.getEncoded()));

        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        final EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
        final PublicKey publicKey2 = keyFactory.generatePublic(publicKeySpec);

        System.out.println(ConverterHelper.bytesToHex(publicKey2.getEncoded()));
    }

    @Test
    void keySpecToPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        final PrivateKey privateKey = keyPairGenerator.generateKeyPair().getPrivate();

        System.out.println(ConverterHelper.bytesToHex(privateKey.getEncoded()));

        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        final EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
        final PrivateKey privateKey2 = keyFactory.generatePrivate(privateKeySpec);

        System.out.println(ConverterHelper.bytesToHex(privateKey2.getEncoded()));
    }

    @Test
    void privateKeyToKeySpec() throws NoSuchAlgorithmException, InvalidKeySpecException {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        final PrivateKey privateKey = keyPairGenerator.generateKeyPair().getPrivate();
        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        final RSAPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
    }

    @Test
    void newSecureRandom() {
        final SecureRandom secureRandom = new SecureRandom();
        final int randomValue = secureRandom.nextInt();
        System.out.println("random value: " + randomValue);
    }

    @Test
    void secureRandom() throws NoSuchAlgorithmException {
        final SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        final int randomValue = secureRandom.nextInt();
        System.out.println("random value: " + randomValue);
    }

    @Test
    void microsoftSecureRandom() throws NoSuchAlgorithmException, NoSuchProviderException {
        final SecureRandom secureRandom = SecureRandom.getInstance("Windows-PRNG", "SunMSCAPI");
        final int randomValue = secureRandom.nextInt();
        System.out.println("random value: " + randomValue);
    }

    @Test
    void secureRandomWithSeed() throws NoSuchAlgorithmException {
        final SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        final byte[] seed = secureRandom.generateSeed(256);
        secureRandom.setSeed(seed);
        final int randomValue = secureRandom.nextInt();
        System.out.println("random value: " + randomValue);
    }

    @Test
    void algorithmParameters() throws NoSuchAlgorithmException, InvalidParameterSpecException, IOException {
        final BigInteger p = new BigInteger("D24700960FFA32D3F1557344E5871"
                + "01237532CC641646ED7A7C104743377F6D46251698B665CE2A6"
                + "CBAB6714C2569A7D2CA22C0CF03FA40AC930201090202020", 16);
        final BigInteger q = new BigInteger("09", 16);
        final BigInteger g = new BigInteger("512");
        final DSAParameterSpec dsaParameterSpec = new DSAParameterSpec(p, q, g);
        final AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("DSA");
        algorithmParameters.init(dsaParameterSpec);

        System.out.println(ConverterHelper.bytesToHex(algorithmParameters.getEncoded()));
    }

    @Test
    void algorithmParameterGenerator() throws NoSuchAlgorithmException, InvalidParameterSpecException {
        final AlgorithmParameterGenerator algorithmParameterGenerator = AlgorithmParameterGenerator.getInstance("DSA");
        final AlgorithmParameters algorithmParameters = algorithmParameterGenerator.generateParameters();
        final DSAParameterSpec parameterSpec = algorithmParameters.getParameterSpec(DSAParameterSpec.class);
        final BigInteger p = parameterSpec.getP();
        final BigInteger q = parameterSpec.getQ();
        final BigInteger g = parameterSpec.getG();

        System.out.println("P: " + p);
        System.out.println("Q: " + q);
        System.out.println("G: " + g);
    }

    @Test
    void readCertificate() throws IOException, CertificateException {
        try (final InputStream is = Files.newInputStream(certificateFile)) {
            final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            final Certificate certificate = certificateFactory.generateCertificate(is);
            System.out.println(certificate);
        }
    }

    @Test
    void certPath() throws IOException, CertificateException, URISyntaxException {
        final Path certificateFile2 = FILE_SYSTEM.provider().getPath(Thread.currentThread().getContextClassLoader().getResource("jca.2.crt").toURI());

        try (final InputStream is = Files.newInputStream(certificateFile);
             final InputStream is2 = Files.newInputStream(certificateFile2)) {
            final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

            final List<Certificate> certificateList = new ArrayList<>();
            final Certificate certificate = certificateFactory.generateCertificate(is);
            certificateList.add(certificate);
            final Certificate certificate2 = certificateFactory.generateCertificate(is2);
            certificateList.add(certificate2);

            final CertPath certPath = certificateFactory.generateCertPath(certificateList);
            System.out.println(certPath);
        }
    }

    @Test
    void pkcs8EncodedKeySpec() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        final byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile);
        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        final EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        final PrivateKey privateKey = keyFactory.generatePrivate(encodedKeySpec);
        final Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(privateKey);
        signature.update("Hello world!".getBytes());
        final byte[] signatureData = signature.sign();

        System.out.println(ConverterHelper.bytesToHex(signatureData));
    }
}
