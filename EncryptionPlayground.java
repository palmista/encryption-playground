import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class EncryptionPlayground {
    

    public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, 
            IllegalBlockSizeException, BadPaddingException, GeneralSecurityException, IOException, Exception {

        // AES.generateKey(256);
        // AES.encryptFile("ClearText/clear", "EncryptedFiles/encrypted", "SymmetricKey/secretKey");
        // AES.decryptFile("EncryptedFiles/encrypted", "DecryptedFiles/decrypted", "SymmetricKey/secretKey");

        // RSA.generateKeyPair(2048);
        // RSA.encryptFile("ClearText/cleartext.txt", "EncryptedFiles/encrypted", "KeyPair/publicKey");
        // RSA.decryptFile("EncryptedFiles/encrypted", "DecryptedFiles/decrypted", "KeyPair/privateKey");
    }
}
