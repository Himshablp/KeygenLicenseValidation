package liberin.poc.keygenLicenseValidation;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.util.encoders.Hex;
import org.json.JSONException;
import org.json.JSONObject;



public class KeygenLicenseValidationBegin {

	private static final String ALGORITHM = "aes-256-gcm+ed25519";
	private static final String LICENSE_FILE_PATH = "D:\\Java Program\\keygen_license validation\\example-java-cryptographic-license-files\\src\\main\\java\\sh\\keygen\\example\\license.lic";
	private static final String LICENSE_KEY = "key/NkRGQjE1LTY1OTdGQy1CN0RCQjYtRTM0REFCLTlENzdDMC1WMw==.OGOk55LkFOM4xWFKqNj9jtAD1Q0TR2A6aqUzdbsgYt4nsTtxZZ9FtlCuk8tjxM1jNXzTI_wTDK846-VEJz0xCw==";
	private static final String PUBLICKEY = "7db6847718ec89e7be8ab88e60ef629339e752b9233231097ecbb98f2cda52b1";

	public static void validate(String args[]) {
		String licenseFilePath = LICENSE_FILE_PATH;
		String encodedPayload = readlicenseFile()[0];
		String licenseKey = LICENSE_KEY;
		String publicKey = PUBLICKEY;

		byte[] payloadBytes = Base64.getDecoder().decode(encodedPayload);
		String payload = new String(payloadBytes);
		String encryptedData = "";
		String encodedSignature = "";
		String algorithm = "";

		try {
			JSONObject attrs = new JSONObject(payload);
			encryptedData = (String) attrs.get("enc");
			encodedSignature = (String) attrs.get("sig");
			algorithm = (String) attrs.get("alg");
		} catch (JSONException e) {
			System.out.println(String.format("Failed to parse license file: %s", e.getMessage()));

			return;
		}

		// Verify license file algorithm
		if (!algorithm.equals(ALGORITHM)) {
			System.out.println("Unsupported algorithm");

			return;
		}

		// Decode base64 signature and asigning data to byte arrays
		byte[] signatureBytes = Base64.getDecoder().decode(encodedSignature);
		String signingData = String.format("license/%s", encryptedData);
		byte[] signingDataBytes = signingData.getBytes();

		// Convert hex-encoded public key to a byte array
		byte[] publicKeyBytes = Hex.decode(publicKey);

		// Set up Ed25519 verifier
		Ed25519PublicKeyParameters verifierParams = new Ed25519PublicKeyParameters(publicKeyBytes, 0);
		Ed25519Signer verifier = new Ed25519Signer();

		verifier.init(false, verifierParams);
		verifier.update(signingDataBytes, 0, signingDataBytes.length);

		// Verify the signature
		boolean ok = verifier.verifySignature(signatureBytes);
		if (ok) {
			System.out.println("License file signature is valid!");

			// The decrypted plaintext dataset
			String plaintext = "";

			byte[] iv = null;
			byte[] tag = null;

			// Parse the encrypted data
			String encodedCiphertext = encryptedData.split("\\.", 3)[0];
			String encodedIv = encryptedData.split("\\.", 3)[1];
			String encodedTag = encryptedData.split("\\.", 3)[2];

			// Decrypt the license file
			try {

				// Decode ciphertext, IV and tag to byte arrays
				byte[] ciphertext = Base64.getDecoder().decode(encodedCiphertext);
				iv = Base64.getDecoder().decode(encodedIv);
				tag = Base64.getDecoder().decode(encodedTag);
				byte[] key = DecryptingData.hashLicenseKey(licenseKey);

				plaintext = decryptLicense(ciphertext, iv, tag, key);

				System.out.println(plaintext);

			} catch (IllegalArgumentException | IllegalStateException | DataLengthException
					| InvalidCipherTextException e) {
				System.out.println(String.format("Failed to decrypt license file: %s", e.getMessage()));

				return;
			}

			System.out.println("License file was successfully decrypted!");
			System.out.println(String.format("> Decrypted: %s", plaintext));

			JSONObject jsonObject = new JSONObject(plaintext);
			JSONObject data = jsonObject.getJSONObject("data");
			JSONObject attributes = data.getJSONObject("attributes");
			JSONObject metadata = attributes.getJSONObject("metadata");
			metadata.remove("timestamp");
			metadata.put("timestamp", formatDate(System.currentTimeMillis()));

			String reEncryptedData = EncryptingData.encryptData(licenseKey, jsonObject.toString(), iv); // +"."+encodedIv+"."+encodedTag;

			KeygenLicenseValidationBegin.writeLicenseFile(licenseFilePath,encodedPayload, reEncryptedData);

			ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

			// Schedule the task to run every 1 minutes
			byte[] initvector = Base64.getDecoder().decode(encodedIv);
			scheduler.scheduleAtFixedRate(() -> {
				// Run the task in a new thread
				new Thread(() -> schedulledProcess(encodedPayload, licenseKey, initvector)).start();
			}, 0, 1, TimeUnit.MINUTES);

		} else {
			System.out.println("License file signature is invalid!");
		}
	}

	private static void schedulledProcess(String encodedPayload, String licenseKey, byte[] iv) {
		String licenseFilePath = LICENSE_FILE_PATH;
		String readEncryptedData = readlicenseFile()[1];
		String newDecrptedData = DecryptingData.decryptData(licenseKey, readEncryptedData, iv);
		JSONObject jsonObject = new JSONObject(newDecrptedData);
		JSONObject data = jsonObject.getJSONObject("data");
		JSONObject attributes = data.getJSONObject("attributes");

		JSONObject metadata = attributes.getJSONObject("metadata");
		String storedTimeStamp = metadata.getString("timestamp");
		System.out.println("Stored TimeStamp is :- " + storedTimeStamp);

		String newCurrentTimeStamp = formatDate(System.currentTimeMillis());
		System.out.println("New TimeStamp is:- " + newCurrentTimeStamp);
		String expiryDateTime = attributes.getString("expiry");
		System.out.println(expiryDateTime);
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
		Date parsedStoredDate = null;
		Date parsedCurrentDate = null;
		try {
			parsedStoredDate = dateFormat.parse(storedTimeStamp);
			parsedCurrentDate = dateFormat.parse(newCurrentTimeStamp);
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		if (parsedStoredDate.before(parsedCurrentDate)) {
			metadata.remove("timestamp");
			metadata.put("timestamp", newCurrentTimeStamp);
		} else {
			ClassLoadPopulation.playSiren();
		}

		String reEncryptedData = EncryptingData.encryptData(licenseKey, jsonObject.toString(), iv); // +"."+encodedIv+"."+encodedTag;

		KeygenLicenseValidationBegin.writeLicenseFile(licenseFilePath,encodedPayload, reEncryptedData);
	}

	private static String[] readlicenseFile() {
		String licenseFilePath = LICENSE_FILE_PATH;
		String[] readArray = new String[2];
		try {
			BufferedReader licenseReader = new BufferedReader(new FileReader(new File(licenseFilePath)));
			readArray[0] = licenseReader.readLine();
			readArray[1] = licenseReader.readLine();

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return readArray;
	}

	private static void writeLicenseFile(String filePath, String encodedPayload, String reEncryptedData) {
		try {
			BufferedWriter licenseWriter = new BufferedWriter(new FileWriter(new File(filePath)));
			String[] stringArr = new String[2];
			stringArr[0] = encodedPayload;
			stringArr[1] = reEncryptedData;
			licenseWriter.write(stringArr[0]);
			licenseWriter.newLine();
			licenseWriter.write(stringArr[1]);
			licenseWriter.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private static String decryptLicense(byte[] ciphertext, byte[] iv, byte[] tag, byte[] key)
			throws InvalidCipherTextException {
		String plaintext;
		// Set up AES-256-GCM
		AEADParameters cipherParams = new AEADParameters(new KeyParameter(key), 128, iv, null);
		GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());

		cipher.init(false, cipherParams);

		// Concat ciphertext and authentication tag to produce cipher input
		byte[] input = new byte[ciphertext.length + tag.length];

		System.arraycopy(ciphertext, 0, input, 0, ciphertext.length);
		System.arraycopy(tag, 0, input, ciphertext.length, tag.length);

		// Decrypt the ciphertext
		byte[] output = new byte[cipher.getOutputSize(input.length)];

		int len = cipher.processBytes(input, 0, input.length, output, 0);

		// Validate authentication tag
		cipher.doFinal(output, len);

		plaintext = new String(output);
		return plaintext;
	}

	public static String formatDate(long timestamp) {
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
		return sdf.format(new Date(timestamp));
	}

}