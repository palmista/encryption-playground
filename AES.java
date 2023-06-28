import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class AES {

    private static SecretKeySpec getKey(String filename, String algorithm) throws IOException {

        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        return new SecretKeySpec(keyBytes, algorithm);

    }

    
    /** 
     * @param lenghtInBits desired key length (in bits)
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws IOException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static void generateKey(int lenghtInBits)
            throws NoSuchAlgorithmException, NoSuchPaddingException, IOException, IllegalBlockSizeException,
            BadPaddingException {

        SecureRandom rnd = new SecureRandom();
        byte[] key = new byte[lenghtInBits / 8];
        rnd.nextBytes(key);

        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        File keyPath = new File("SymmetricKey/secretKey");
        IO.writeToFile(keyPath, secretKey.getEncoded());
        System.out.println("AES key was successfully created in:  " + keyPath.getPath());

    }

    
    /** 
     * @param input path to cleartext file
     * @param output path where the encrypted file should be stored
     * @param key path to key file
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static void encryptFile(String input, String output, String key)
            throws IOException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        File inputFile = new File(input);
        File outputFile = new File(output);
        SecretKeySpec aesKey = getKey(key, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        IO.writeToFile(outputFile, cipher.doFinal(IO.getFileInBytes(inputFile)));
        System.out.println(inputFile.getPath() + "  was successfully AES-encrypted to:  " + outputFile.getPath());

    }

    
    /** 
     * @param input path to encrypted file
     * @param output path where the decrypted file should be stored
     * @param key path to key file
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static void decryptFile(String input, String output, String key)
            throws IOException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        File inputFile = new File(input);
        File outputFile = new File(output);
        SecretKeySpec aesKey = getKey(key, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        IO.writeToFile(outputFile, cipher.doFinal(IO.getFileInBytes(inputFile)));
        System.out.println(inputFile.getPath() + "  was successfully AES-encrypted to:  " + outputFile.getPath());

    }

}