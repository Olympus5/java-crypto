package fr.olympus5.helper;

public class ConverterHelper {

    private static final char[] HEX_DIGIT = "0123456789ABCDEF".toCharArray();

    public static String bytesToHex(final byte[] bytes) {
        final char[] hex = new char[bytes.length * 2];
        for (int i = 0, c = bytes.length; i < c; i++) {
            hex[i * 2] = HEX_DIGIT[(bytes[i] >>> 4) & 0x0F];
            hex[i * 2 + 1] = HEX_DIGIT[bytes[i] & 0x0F];
        }
        return new String(hex);
    }
}
