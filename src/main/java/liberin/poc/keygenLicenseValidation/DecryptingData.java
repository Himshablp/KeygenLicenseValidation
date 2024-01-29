package liberin.poc.keygenLicenseValidation;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

public class DecryptingData {

    public static String decryptData(String licenseKey, String encryptedDataString, byte[] iv) {
        byte[] encryptedData = Base64.getDecoder().decode(encryptedDataString);
        byte[] key = hashLicenseKey(licenseKey);
        String decryptedData = decryptData(encryptedData, key, iv);
        System.out.println("Decrypted Data: " + decryptedData);
        return decryptedData;
    }

    public static byte[] hashLicenseKey(String licenseKey) {
        try {
            byte[] licenseKeyBytes = licenseKey.getBytes();
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            return sha256.digest(licenseKeyBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to hash license key: " + e.getMessage());
        }
    }

    private static String decryptData(byte[] ciphertext, byte[] key, byte[] iv) {
        try {
            AEADParameters cipherParams = new AEADParameters(new KeyParameter(key), 128, iv, null);
            GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
            cipher.init(false, cipherParams);
            byte[] output = new byte[cipher.getOutputSize(ciphertext.length)];
            int len = cipher.processBytes(ciphertext, 0, ciphertext.length, output, 0);
            cipher.doFinal(output, len);
            return new String(output);
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed: " + e.getMessage());
        }
    }
}
