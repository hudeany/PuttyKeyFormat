package de.soderer.utilities;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.LineNumberReader;
import java.io.OutputStream;
import java.io.StringReader;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Writer for PuTTY ".ppk" keyfiles<br />
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
public class PuttyKeyWriter implements Closeable {
	private final OutputStream outputStream;

	public PuttyKeyWriter(final OutputStream outputStream) throws IOException {
		this.outputStream = outputStream;
	}

	public void writeKey(final PuttyKey puttyKey, final char[] password) throws Exception {
		final String algorithmName = puttyKey.getAlgorithm();
		final byte[] passwordBytes = password == null || password.length == 0 ? null : toBytes(password, "ISO-8859-1");

		final byte[] publicKeyBytes = puttyKey.getPublicKeyBytes();
		byte[] privateKeyBytes = puttyKey.getPrivateKeyBytes();

		// padding up to multiple of 16 bytes for AES/CBC/NoPadding encryption
		privateKeyBytes = addLengthCodedPadding(privateKeyBytes, 16);

		final String macHash = calculateMacChecksum(passwordBytes, algorithmName, puttyKey.getComment(), publicKeyBytes, privateKeyBytes);

		if (passwordBytes != null) {
			final byte[] puttyKeyEncryptionKey = stretchPassword(passwordBytes);

			final Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(puttyKeyEncryptionKey, 0, 32, "AES"), new IvParameterSpec(new byte[16])); // initial vector=0

			privateKeyBytes = cipher.doFinal(privateKeyBytes);
		}

		final String publicKeyBase64 = toWrappedBase64(publicKeyBytes, 64, "\r\n");
		final String privateKeyBase64 = toWrappedBase64(privateKeyBytes, 64, "\r\n");

		final StringBuilder content = new StringBuilder();
		content.append("PuTTY-User-Key-File-2: ").append(algorithmName).append("\r\n");
		content.append("Encryption: ").append(passwordBytes == null ? "none" : "aes256-cbc").append("\r\n");
		content.append("Comment: ").append(puttyKey.getComment()).append("\r\n");
		content.append("Public-Lines: ").append(getLineCount(publicKeyBase64)).append("\r\n");
		content.append(publicKeyBase64).append("\r\n");
		content.append("Private-Lines: ").append(getLineCount(privateKeyBase64)).append("\r\n");
		content.append(privateKeyBase64).append("\r\n");
		content.append("Private-MAC: ").append(macHash);

		outputStream.write(content.toString().getBytes("ISO-8859-1"));
	}

	private static byte[] stretchPassword(final byte[] passwordByteArray) throws NoSuchAlgorithmException {
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

	private static String calculateMacChecksum(final byte[] passwordBytes, final String keyType, final String comment, final byte[] publicKey, final byte[] privateKey) throws Exception {
		final String encryptionType = passwordBytes == null ? "none" : "aes256-cbc";
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

		final byte[] keyTypeBytes = keyType.getBytes("ISO-8859-1");
		data.writeInt(keyTypeBytes.length);
		data.write(keyTypeBytes);

		final byte[] encryptionTypeBytes = encryptionType.getBytes("ISO-8859-1");
		data.writeInt(encryptionTypeBytes.length);
		data.write(encryptionTypeBytes);

		final byte[] commentBytes = comment.getBytes("ISO-8859-1");
		data.writeInt(commentBytes.length);
		data.write(commentBytes);

		data.writeInt(publicKey.length);
		data.write(publicKey);

		data.writeInt(privateKey.length);
		data.write(privateKey);

		return toHexString(mac.doFinal(out.toByteArray())).toLowerCase();
	}

	public static byte[] addLengthCodedPadding(byte[] data, final int paddingSize) {
		final byte[] dataPadded;
		if (data.length % paddingSize != 0) {
			dataPadded = new byte[((data.length / paddingSize) + 1) * paddingSize];
		} else {
			dataPadded = new byte[data.length + paddingSize];
		}
		for (int i = 0; i < data.length; i++) {
			dataPadded[i] = data[i];
		}
		final byte padValue = (byte) (dataPadded.length - data.length);
		for (int i = data.length; i < dataPadded.length; i++) {
			dataPadded[i] = padValue;
		}
		data = dataPadded;
		return data;
	}

	/**
	 * Converts byte array to base64 with linebreaks
	 */
	private static String toWrappedBase64(final byte[] byteArray, final int maxLineLength, final String lineBreak) {
		return Base64.getMimeEncoder(maxLineLength, lineBreak.getBytes(Charset.forName("ISO-8859-1"))).encodeToString(byteArray);
	}

	private static String toHexString(final byte[] data) {
		final StringBuilder returnString = new StringBuilder();
		for (final byte dataByte : data) {
			returnString.append(String.format("%02X", dataByte));
		}
		return returnString.toString();
	}

	private static int getLineCount(final String dataString) throws IOException {
		if (dataString == null) {
			return 0;
		} else if ("".equals(dataString)) {
			return 1;
		} else {
			try (LineNumberReader lineNumberReader = new LineNumberReader(new StringReader(dataString))) {
				while (lineNumberReader.readLine() != null) {
					// do nothing
				}
				return lineNumberReader.getLineNumber();
			}
		}
	}

	private static byte[] toBytes(final char[] chars, final String encoding) {
		final ByteBuffer byteBuffer = Charset.forName(encoding).encode(CharBuffer.wrap(chars));
		final byte[] bytes = Arrays.copyOfRange(byteBuffer.array(), byteBuffer.position(), byteBuffer.limit());
		Arrays.fill(byteBuffer.array(), (byte) 0); // clear sensitive data
		return bytes;
	}

	@Override
	public void close() {
		try {
			outputStream.close();
		} catch (final Exception e) {
			e.printStackTrace();
		}
	}
}
