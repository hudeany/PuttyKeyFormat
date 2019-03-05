package de.soderer.utilities;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.LineNumberReader;
import java.io.OutputStream;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.ws.WebServiceException;

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

	public void writePuttyKeyFormat(final PuttyKey puttyKey, final String password) throws Exception {
		final byte[] passwordBytes = password == null ? null : password.getBytes("ISO-8859-1");

		final byte[] publicKeyBytes = puttyKey.getPublicKeyBytes();
		byte[] privateKeyBytes = puttyKey.getPrivateKeyBytes();

		// padding up to multiple of 16 bytes for AES/CBC/NoPadding encryption
		if (passwordBytes != null && privateKeyBytes.length % 16 != 0) {
			final byte[] privateKeyBytesPadded = new byte[((privateKeyBytes.length / 16) + 1) * 16];
			for (int i = 0; i < privateKeyBytes.length; i++) {
				privateKeyBytesPadded[i] = privateKeyBytes[i];
			}
			final byte[] randomArray = new byte[privateKeyBytesPadded.length - privateKeyBytes.length];
			new SecureRandom().nextBytes(randomArray);
			for (int i = 0; i < randomArray.length; i++) {
				privateKeyBytesPadded[privateKeyBytes.length + i] = randomArray[i];
			}
			privateKeyBytes = privateKeyBytesPadded;
		}

		final String macHash = calculateMacChecksum(passwordBytes, puttyKey.getAlgorithm(), password == null ? "none" : "aes256-cbc", puttyKey.getComment(), publicKeyBytes, privateKeyBytes);

		if (passwordBytes != null) {
			final byte[] puttyKeyEncryptionKey = getPuttyPrivateKeyEncryptionKey(passwordBytes);

			final Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(puttyKeyEncryptionKey, 0, 32, "AES"), new IvParameterSpec(new byte[16])); // initial vector=0

			privateKeyBytes = cipher.doFinal(privateKeyBytes);
		}

		final String publicKeyBase64 = toWrappedBase64(publicKeyBytes, "\r\n");
		final String privateKeyBase64 = toWrappedBase64(privateKeyBytes, "\r\n");

		final StringBuilder content = new StringBuilder();
		content.append("PuTTY-User-Key-File-2: ").append(puttyKey.getAlgorithm()).append("\r\n");
		content.append("Encryption: ").append(password == null ? "none" : "aes256-cbc").append("\r\n");
		content.append("Comment: ").append(puttyKey.getComment()).append("\r\n");
		content.append("Public-Lines: ").append(getLineCount(publicKeyBase64)).append("\r\n");
		content.append(publicKeyBase64).append("\r\n");
		content.append("Private-Lines: ").append(getLineCount(privateKeyBase64)).append("\r\n");
		content.append(privateKeyBase64).append("\r\n");
		content.append("Private-MAC: ").append(macHash);

		outputStream.write(content.toString().getBytes("ISO-8859-1"));
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

	/**
	 * Converts this key into unprotected DER format for OpenSSH keys<br />
	 * <br />
	 * <b>Use with caution, because this key format is not protected by any password</>
	 */
	public void writeUnprotectedDerFormat(final PuttyKey puttyKey) throws Exception {
		if (PuttyKey.SSH_CIPHER_NAME_RSA.equalsIgnoreCase(puttyKey.getAlgorithm())) {
			outputStream.write(createRsaBinaryKey(puttyKey));
		} else if (PuttyKey.SSH_CIPHER_NAME_DSA.equalsIgnoreCase(puttyKey.getAlgorithm())) {
			outputStream.write(createDssBinaryKey(puttyKey));
		} else {
			throw new IllegalArgumentException("Unsupported cipher: " + puttyKey.getAlgorithm());
		}
	}

	/**
	 * Converts this key into unprotected PEM format for OpenSSH keys<br />
	 * <br />
	 * <b>Use with caution, because this key format is not protected by any password</>
	 */
	public void writeUnprotectedPemFormat(final PuttyKey puttyKey) throws Exception {
		if (PuttyKey.SSH_CIPHER_NAME_RSA.equalsIgnoreCase(puttyKey.getAlgorithm())) {
			outputStream.write("-----BEGIN RSA PRIVATE KEY-----\n".getBytes("ISO-8859-1"));
			outputStream.write(toWrappedBase64(createRsaBinaryKey(puttyKey), "\n").getBytes("ISO-8859-1"));
			outputStream.write("\n".getBytes("ISO-8859-1"));
			outputStream.write("-----END RSA PRIVATE KEY-----\n".getBytes("ISO-8859-1"));
		} else if (PuttyKey.SSH_CIPHER_NAME_DSA.equalsIgnoreCase(puttyKey.getAlgorithm())) {
			outputStream.write("-----BEGIN DSA PRIVATE KEY-----\n".getBytes("ISO-8859-1"));
			outputStream.write(toWrappedBase64(createDssBinaryKey(puttyKey), "\n").getBytes("ISO-8859-1"));
			outputStream.write("\n".getBytes("ISO-8859-1"));
			outputStream.write("-----END DSA PRIVATE KEY-----\n".getBytes("ISO-8859-1"));
		} else {
			throw new IllegalArgumentException("Unsupported cipher: " + puttyKey.getAlgorithm());
		}
	}

	private byte[] createRsaBinaryKey(final PuttyKey puttyKey) throws Exception, IOException {
		final RSAPrivateCrtKey privateKey = ((RSAPrivateCrtKey) puttyKey.getKeyPair().getPrivate());

		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		writeBigIntegerToStream(out, BigInteger.ZERO);
		writeBigIntegerToStream(out, privateKey.getModulus());
		writeBigIntegerToStream(out, privateKey.getPublicExponent());
		writeBigIntegerToStream(out, privateKey.getPrivateExponent());
		writeBigIntegerToStream(out, privateKey.getPrimeP());
		writeBigIntegerToStream(out, privateKey.getPrimeQ());
		writeBigIntegerToStream(out, privateKey.getPrimeExponentP());
		writeBigIntegerToStream(out, privateKey.getPrimeExponentQ());
		writeBigIntegerToStream(out, privateKey.getCrtCoefficient());
		return createByteSequence(out.toByteArray());
	}

	private byte[] createDssBinaryKey(final PuttyKey puttyKey) throws Exception, IOException {
		final DSAPublicKey publicKey = ((DSAPublicKey) puttyKey.getKeyPair().getPublic());
		final DSAPrivateKey privateKey = ((DSAPrivateKey) puttyKey.getKeyPair().getPrivate());

		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		writeBigIntegerToStream(out, BigInteger.ZERO);
		writeBigIntegerToStream(out, privateKey.getParams().getP());
		writeBigIntegerToStream(out, privateKey.getParams().getQ());
		writeBigIntegerToStream(out, privateKey.getParams().getG());
		writeBigIntegerToStream(out, publicKey.getY());
		writeBigIntegerToStream(out, privateKey.getX());
		return createByteSequence(out.toByteArray());
	}

	/**
	 * Converts byte array to base64 with 64 chars per line
	 */
	private static String toWrappedBase64(final byte[] byteArray, final String lineBreak) {
		return Base64.getMimeEncoder(64, lineBreak.getBytes(Charset.forName("ISO-8859-1"))).encodeToString(byteArray);
	}

	private static byte[] createByteSequence(final byte[] data) throws IOException {
		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		out.write(0x30);
		final int len = data.length;
		if (len < 0x80) {
			out.write(len);
		} else {
			final int bytes = getByteEncodedLength(len);
			out.write(0x80 | bytes);
			for (int i = bytes - 1; i >= 0; i--) {
				out.write((len >> (8 * i)) & 0xFF);
			}
		}
		out.write(data);
		return out.toByteArray();
	}

	private static int getByteEncodedLength(int value) {
		int lengthInBytes = 0;
		while (value > 0) {
			lengthInBytes++;
			value >>= 8;
		}
		return lengthInBytes;
	}

	private static void writeBigIntegerToStream(final ByteArrayOutputStream out, final BigInteger bigIntegerValue) throws IOException {
		out.write(0x02);
		final byte[] bytes = bigIntegerValue.toByteArray();
		final int len = bytes.length;
		if (len < 0x80) {
			out.write(len);
		} else {
			final int bytes1 = getByteEncodedLength(len);
			out.write(0x80 | bytes1);
			for (int i1 = bytes1 - 1; i1 >= 0; i1--) {
				out.write((len >> (8 * i1)) & 0xFF);
			}
		}
		out.write(bytes);
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

	@Override
	public void close() throws WebServiceException {
		try {
			outputStream.close();
		} catch (final Exception e) {
			e.printStackTrace();
		}
	}
}
