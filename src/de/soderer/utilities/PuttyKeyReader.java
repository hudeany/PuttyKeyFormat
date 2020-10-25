package de.soderer.utilities;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Reader for PuTTY ".ppk" keyfiles<br />
 * <br />
 * PuTTY file format:
 * <pre>
 * PuTTY-User-Key-File-2: xxx
 * Encryption: xxx
 * Comment: xxx
 * Public-Lines: 4
 * &lt;Base64 public key data lines>
 * Private-Lines: 8
 * &lt;Base64 private key data lines>
 * Private-MAC: xxx
 * </pre>
 */
public class PuttyKeyReader implements Closeable {
	private final BufferedReader dataReader;

	public static boolean isPuTTYKeyFile(final File ppkFile) throws IOException {
		try (BufferedReader puttKeyReader = new BufferedReader(new FileReader(ppkFile))) {
			String line;
			while ((line = puttKeyReader.readLine()) != null) {
				if (line.startsWith("PuTTY-User-Key-File-")) {
					return true;
				}
			}
			return false;
		}
	}

	public PuttyKeyReader(final InputStream inputStream) {
		dataReader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.ISO_8859_1));
	}

	public PuttyKey readKey(final char[] password) throws Exception {
		final byte[] passwordByteArray;
		if (password != null && password.length > 0)  {
			final CharBuffer charBuffer = CharBuffer.wrap(password);
			final ByteBuffer byteBuffer = StandardCharsets.ISO_8859_1.encode(charBuffer);
			passwordByteArray = Arrays.copyOfRange(byteBuffer.array(), byteBuffer.position(), byteBuffer.limit());
		} else {
			passwordByteArray = null;
		}

		final Map<String, String> headers = new HashMap<>();
		final Map<String, StringBuilder> data = new HashMap<>();
		String latestHeaderName = null;
		String nextLine;
		while ((nextLine = dataReader.readLine()) != null) {
			final int indexOfHeaderSeparator = nextLine.indexOf(": ");
			if (indexOfHeaderSeparator > 0) {
				final String headerName = nextLine.substring(0, indexOfHeaderSeparator).trim();
				headers.put(headerName, nextLine.substring(indexOfHeaderSeparator + 2));
				latestHeaderName = headerName;
			} else {
				if (!data.containsKey(latestHeaderName)) {
					data.put(latestHeaderName, new StringBuilder());
				}
				data.get(latestHeaderName).append(nextLine);
			}
		}

		String puttyKeyType = null;
		for (final String headerName : headers.keySet()) {
			if (headerName.startsWith("PuTTY-User-Key-File-")) {
				puttyKeyType = headerName;
				break;
			}
		}
		if (puttyKeyType == null || data.size() < 1) {
			throw new Exception("No PuTTY key found");
		}
		if (!"PuTTY-User-Key-File-2".equals(puttyKeyType)) {
			throw new Exception("Unsupported PuTTY key type (Only \"PuTTY-User-Key-File-2\" is supported): " + puttyKeyType);
		}
		final String chipherName = headers.get("PuTTY-User-Key-File-2");
		if (chipherName == null || "".equals(chipherName)) {
			throw new Exception("Missing cipher name");
		}
		if (!KeyPairUtilities.SSH_ALGORITHM_NAME_RSA.equalsIgnoreCase(chipherName)
				&& !KeyPairUtilities.SSH_ALGORITHM_NAME_DSA.equalsIgnoreCase(chipherName)
				&& !KeyPairUtilities.SSH_ALGORITHM_NAME_ECDSA_NISTP256.equalsIgnoreCase(chipherName)
				&& !KeyPairUtilities.SSH_ALGORITHM_NAME_ECDSA_NISTP384.equalsIgnoreCase(chipherName)
				&& !KeyPairUtilities.SSH_ALGORITHM_NAME_ECDSA_NISTP521.equalsIgnoreCase(chipherName)) {
			throw new Exception("Unsupported chipher: " + chipherName);
		}

		final Decoder base64Decoder = Base64.getDecoder();

		final byte[] publicKey = base64Decoder.decode(data.get("Public-Lines").toString());

		final String encryptionMethod = headers.get("Encryption");

		byte[] privateKey;
		if (encryptionMethod == null || "".equals(encryptionMethod) || "none".equalsIgnoreCase(encryptionMethod)) {
			privateKey = base64Decoder.decode(data.get("Private-Lines").toString());
		} else if ("aes256-cbc".equalsIgnoreCase(encryptionMethod)) {
			if (passwordByteArray == null) {
				throw new WrongPasswordException();
			}
			try {
				final byte[] puttyKeyEncryptionKey = getPuttyPrivateKeyEncryptionKey(passwordByteArray);

				final Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
				cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(puttyKeyEncryptionKey, 0, 32, "AES"), new IvParameterSpec(new byte[16])); // initial vector=0

				privateKey = cipher.doFinal(base64Decoder.decode(data.get("Private-Lines").toString()));
			} catch (final Exception e) {
				throw new Exception("Cannot decrypt PuTTY private key data", e);
			}
		} else {
			throw new Exception("Unsupported key encryption method: " + headers.get("Encryption"));
		}

		try {
			final String calculatedMacChecksum = calculateMacChecksum(passwordByteArray, headers.get("PuTTY-User-Key-File-2"), headers.get("Encryption"), headers.get("Comment"), publicKey, privateKey);
			final String foundMacChecksum = headers.get("Private-MAC");
			if (foundMacChecksum == null || !foundMacChecksum.equalsIgnoreCase(calculatedMacChecksum)) {
				throw new WrongPasswordException();
			}
		} catch (final WrongPasswordException e) {
			throw e;
		} catch (final Exception e) {
			throw new Exception("Invalid PuTTY key data: " + e.getMessage(), e);
		}

		return new PuttyKey(headers.get("Comment"), chipherName, privateKey, publicKey);
	}

	private static byte[] getPuttyPrivateKeyEncryptionKey(final byte[] passwordByteArray) throws NoSuchAlgorithmException {
		final byte[] puttyKeyEncryptionKey = new byte[32];
		final MessageDigest digest = MessageDigest.getInstance("SHA-1");

		digest.update(new byte[] { 0, 0, 0, 0 });
		digest.update(passwordByteArray);
		final byte[] key1 = digest.digest();

		digest.update(new byte[] { 0, 0, 0, 1 });
		digest.update(passwordByteArray);
		final byte[] key2 = digest.digest();

		System.arraycopy(key1, 0, puttyKeyEncryptionKey, 0, 20);
		System.arraycopy(key2, 0, puttyKeyEncryptionKey, 20, 12);
		return puttyKeyEncryptionKey;
	}

	private static String calculateMacChecksum(final byte[] passwordBytes, final String keyType, final String encryptionType, final String comment, final byte[] publicKey, final byte[] privateKey) throws Exception {
		final MessageDigest digest = MessageDigest.getInstance("SHA-1");
		digest.update("putty-private-key-file-mac-key".getBytes());
		if (passwordBytes != null) {
			digest.update(passwordBytes);
		}
		final byte[] key = digest.digest();

		final Mac mac = Mac.getInstance("HmacSHA1");
		mac.init(new SecretKeySpec(key, 0, 20, mac.getAlgorithm()));

		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		final DataOutputStream data = new DataOutputStream(out);

		final byte[] keyTypeBytes = keyType.getBytes(StandardCharsets.ISO_8859_1);
		data.writeInt(keyTypeBytes.length);
		data.write(keyTypeBytes);

		final byte[] encryptionTypeBytes = encryptionType.getBytes(StandardCharsets.ISO_8859_1);
		data.writeInt(encryptionTypeBytes.length);
		data.write(encryptionTypeBytes);

		final byte[] commentBytes = comment.getBytes(StandardCharsets.ISO_8859_1);
		data.writeInt(commentBytes.length);
		data.write(commentBytes);

		data.writeInt(publicKey.length);
		data.write(publicKey);

		data.writeInt(privateKey.length);
		data.write(privateKey);

		return toHexString(mac.doFinal(out.toByteArray())).toLowerCase();
	}

	private static String toHexString(final byte[] data) {
		final StringBuilder returnString = new StringBuilder();
		for (final byte dataByte : data) {
			returnString.append(String.format("%02X", dataByte));
		}
		return returnString.toString();
	}

	@Override
	public void close() throws IOException {
		try {
			dataReader.close();
		} catch (final Exception e) {
			e.printStackTrace();
		}
	}
}
