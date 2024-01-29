package liberin.poc.keygenLicenseValidation;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

public class EncryptingData {

    public static String encryptData(String licenseKey, String plaintextData, byte[] iv) {
        byte[] key = hashLicenseKey(licenseKey);
        byte[] ciphertext = encryptData(plaintextData.getBytes(), key, iv);
        return Base64.getEncoder().encodeToString(ciphertext);
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

    private static byte[] encryptData(byte[] data, byte[] key, byte[] iv) {
        try {
            AEADParameters cipherParams = new AEADParameters(new KeyParameter(key), 128, iv, null);
            GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
            cipher.init(true, cipherParams);
            byte[] output = new byte[cipher.getOutputSize(data.length)];
            int len = cipher.processBytes(data, 0, data.length, output, 0);
            cipher.doFinal(output, len);
            return output;
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed: " + e.getMessage());
        }
    }
}
