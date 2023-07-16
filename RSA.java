import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

public class RSA {

    private static PublicKey getPublic(String filename, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {

        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(algorithm);
        return kf.generatePublic(spec);

    }

    private static PrivateKey getPrivate(String filename, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {

        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(algorithm);
        return kf.generatePrivate(spec);
        
    }
    
    /** 
     * @param lenghtInBits desired key length (in bits)
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws IOException
     */
    public static void generateKeyPair(int lenghtInBits) throws NoSuchAlgorithmException, IllegalBlockSizeException, 
            BadPaddingException, IOException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(lenghtInBits);
        KeyPair pair = generator.generateKeyPair();

        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();

        IO.writeToFile(new File("KeyPair/privateKey"), privateKey.getEncoded());
        IO.writeToFile(new File("KeyPair/publicKey"), publicKey.getEncoded());
    }

    
    /** 
     * @param keystorePath path to keystore file
     * @param alias the alias which is to export
     * @param password keystore password
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws IOException
     * @throws UnrecoverableKeyException
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static void getKeysFromKeystore(String keystorePath, String alias, String password) throws NoSuchAlgorithmException, NoSuchProviderException, IOException,
            UnrecoverableKeyException, KeyStoreException, CertificateException, IllegalBlockSizeException, BadPaddingException {
        
        FileInputStream is = new FileInputStream(keystorePath);
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, password.toCharArray());

        // Get public key
        Certificate certificate = keystore.getCertificate(alias);
        PublicKey publicKey = certificate.getPublicKey();
        IO.writeToFile(new File("KeyPair/publicKey"), publicKey.getEncoded());
        IO.writeToFile(new File("KeyPair/certificate.cer"), certificate.getEncoded());

        Key key = keystore.getKey(alias, password.toCharArray());
        if (key instanceof PrivateKey) {
            // new KeyPair(publicKey, (PrivateKey) key);   // Return a key pair (not used)
            IO.writeToFile(new File("KeyPair/privateKey"), key.getEncoded());
        }

    }

    
    /** 
     * @param input path to cleartext file
     * @param output path where the encrypted file should be stored
     * @param key path to key file
     * @throws IOException
     * @throws GeneralSecurityException
     * @throws Exception
     */
    public static void encryptFile(String input, String output, String key) throws IOException, GeneralSecurityException, Exception {
        
        File inputFile = new File(input);
        File outputFile = new File(output);
        PublicKey publicKey = getPublic(key, "RSA");

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        IO.writeToFile(outputFile, cipher.doFinal(IO.getFileInBytes(inputFile)));
        System.out.println(
                inputFile.getPath() + " was successfully RSA-encrypted and stored in: " + outputFile.getPath());
            
    }
    /** 
     * @param input path to encrypted file
     * @param output path where the decrypted file should be stored
     * @param key path to key file
     * @throws IOException
     * @throws GeneralSecurityException
     * @throws Exception
     */
    public static void decryptFile(String input, String output, String key) throws IOException, GeneralSecurityException, Exception {

        File inputFile = new File(input);
        File outputFile = new File(output);
        PrivateKey privateKey = getPrivate(key, "RSA");

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        IO.writeToFile(outputFile, cipher.doFinal(IO.getFileInBytes(inputFile)));
        System.out.println(
            inputFile.getPath() + " was successfully RSA-decrypted and stored in: " + outputFile.getPath());
        
    }


    
    /** 
     * @param file path to file which is to be signed
     * @param key path to key to sign with
     * @param output path where the signature is to be stored
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws InvalidKeySpecException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static void signMessage(String file, String key, String output) throws IOException, NoSuchAlgorithmException, 
            InvalidKeyException, SignatureException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
        
        File originalFile = new File(file);

        //calculate sha256 hash
        byte[] data = Files.readAllBytes(originalFile.toPath());
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(data);
        String checksum = new BigInteger(1, hash).toString(16);
        System.out.println("SHA256 checksum: " + checksum);

        //generate signature (not using the generated hash from above)
        PrivateKey privateKey = getPrivate(key, "RSA");

        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(Files.readAllBytes(originalFile.toPath()));
        byte[] signature = privateSignature.sign();

        IO.writeToFile(new File(output), signature);
    }

    
    /** 
     * @param file path to file that is to be verified
     * @param key path to key
     * @param signatureFile path to the signature file
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static void verifySignature(String file, String key, String signatureFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, 
            InvalidKeyException, SignatureException, IllegalBlockSizeException, BadPaddingException {
        File decryptedFile = new File(file);

        //calculate sha256 hash
        byte[] data = Files.readAllBytes(decryptedFile.toPath());
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(data);
        String checksum = new BigInteger(1, hash).toString(16);
        System.out.println("SHA256 checksum: " + checksum);

        //generate signature (not using the generated hash from above)
        PublicKey publicKey = getPublic(key, "RSA");
        byte[] signature = Files.readAllBytes(new File(signatureFile).toPath());

        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initVerify(publicKey);
        privateSignature.update(Files.readAllBytes(decryptedFile.toPath()));

        System.out.println(privateSignature.verify(signature) ? "Signatures match" : "Signatures don't match");
    }
}