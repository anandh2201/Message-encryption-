import java.util.Scanner;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 * This program demonstrates how to encrypt/decrypt
 * input using the Blowfish
 * Cipher with the Java Cryptography.
 */
public class Blowfish {
    public String key = "Welcome";
    
    public String encrypt(String password) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, UnsupportedEncodingException {
        byte[] KeyData = key.getBytes();
        SecretKeySpec KS = new SecretKeySpec(KeyData, "Blowfish");
        Cipher cipher = Cipher.getInstance("Blowfish");
        cipher.init(Cipher.ENCRYPT_MODE, KS);
        String encryptedtext = Base64.getEncoder().encodeToString(cipher.doFinal(password.getBytes("UTF-8")));
        return encryptedtext;

    }

    public String decrypt(String encryptedtext)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException {
        byte[] KeyData = key.getBytes();
        SecretKeySpec KS = new SecretKeySpec(KeyData, "Blowfish");
        byte[] ecryptedtexttobytes = Base64.getDecoder().decode(encryptedtext);
        Cipher cipher = Cipher.getInstance("Blowfish");
        cipher.init(Cipher.DECRYPT_MODE, KS);
        byte[] decrypted = cipher.doFinal(ecryptedtexttobytes);
        String decryptedString = new String(decrypted, Charset.forName("UTF-8"));
        return decryptedString;

    }

    public static void main(String[] args) throws Exception {
        // final String password = "Knf@123";
//        final String key = "knowledgefactory";
//        Scanner myObj = new Scanner(System.in); // Create a Scanner object
//        System.out.println("Enter username");
//        String password = myObj.nextLine();
//        System.out.println("Password: " + password);
//        Blowfish obj = new Blowfish();
//        String enc_output = obj.encrypt(password, key);
//        System.out.println("Encrypted text: " + enc_output);
//        String dec_output = obj.decrypt(enc_output, key);
//        System.out.println("Decrypted text: " + dec_output);
    }
}

/*
 * Output:Password:Knf @123
 * 
 * Encrypted text:4D THqnctCuk=
 * Decrypted text:Knf @123
 * 
 * Example 2:
 * File Encryption
 * and decryption
 * using
 * Blowfish
 * import java.io.File;
 * import java.io.FileInputStream;
 * import java.io.FileOutputStream;
 * import java.io.InputStream;
 * import java.io.OutputStream;
 * import java.security.Key;
 * import javax.crypto.Cipher;
 * import javax.crypto.spec.SecretKeySpec;
 * 
 * public class BlowfishFileEncryptionDemo {
 * 
 * private static final String ALGORITHM = "Blowfish";
 * private static String key= "knowledgefactory";
 * private static final String SAMPLE_FILE_PATH =
 * "/home/user/Desktop/cryptotest/Sample.txt";
 * private static final String ENCRYPTED_FILE_PATH =
 * "/home/user/Desktop/cryptotest/file.encrypted";
 * private static final String DECRYPTED_FILE_PATH =
 * "/home/user/Desktop/cryptotest/decryptedfile.txt";
 * 
 * public static void main(String[] args) {
 * 
 * File sampleFile = new File(SAMPLE_FILE_PATH);
 * File encryptedFile = new File(ENCRYPTED_FILE_PATH);
 * File decryptedFile = new File(DECRYPTED_FILE_PATH);
 * 
 * try {
 * BlowfishFileEncryptionDemo.encrypt(sampleFile, encryptedFile);
 * BlowfishFileEncryptionDemo.decrypt(encryptedFile, decryptedFile);
 * } catch (Exception e) {
 * e.printStackTrace();
 * }
 * }
 * 
 * public static void encrypt(File sampleFile, File outputFile)
 * throws Exception {
 * doCrypto(Cipher.ENCRYPT_MODE, sampleFile, outputFile);
 * 
 * }
 * 
 * public static void decrypt(File sampleFile, File outputFile)
 * throws Exception {
 * doCrypto(Cipher.DECRYPT_MODE, sampleFile, outputFile);
 * 
 * }
 * 
 * private static void doCrypto(int cipherMode, File sampleFile,
 * File outputFile) throws Exception {
 * 
 * Key secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
 * Cipher cipher = Cipher.getInstance(ALGORITHM);
 * cipher.init(cipherMode, secretKey);
 * 
 * InputStream inputStream = new FileInputStream(sampleFile);
 * byte[] inputBytes = new byte[(int) sampleFile.length()];
 * inputStream.read(inputBytes);
 * 
 * byte[] outputBytes = cipher.doFinal(inputBytes);
 * 
 * OutputStream outputStream = new FileOutputStream(outputFile);
 * outputStream.write(outputBytes);
 * 
 * inputStream.close();
 * outputStream.close();
 * 
 * }
 * }
 */