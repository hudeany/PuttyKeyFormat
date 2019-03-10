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
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
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
	/**
	 * ASN.1 "INTEGER" (0x02 = 2)
	 */
	private static int DER_TAG_INTEGER = 0x02;

	/**
	 * ASN.1 "BIT STRING" (0x03 = 3)
	 */
	private static int DER_TAG_BIT_STRING = 0x03;

	/**
	 * ASN.1 "OCTET STRING" (0x04 = 4)
	 */
	private static int DER_TAG_OCTET_STRING = 0x04;

	/**
	 * ASN.1 "OBJECT" (0x06 = 6)
	 */
	private static int DER_TAG_OBJECT = 0x06;

	/**
	 * ASN.1 "SEQUENCE" (0x30 = 48)
	 */
	private static int DER_TAG_SEQUENCE = 0x30;

	/**
	 * ASN.1 CONTEXT SPECIFIC "cont [ 0 ]" (0xA0 = -96)
	 */
	private static int DER_TAG_CONTEXT_SPECIFIC_0 = 0xA0;

	/**
	 * ASN.1 CONTEXT SPECIFIC "cont [ 1 ]" (0xA1 = -95)
	 */
	private static int DER_TAG_CONTEXT_SPECIFIC_1 = 0xA1;

	private static byte[] OBJECT_IDENTIFIER_secp256r1 = new byte[] { 42, -122, 72, -50, 61, 3, 1, 7 };
	private static byte[] OBJECT_IDENTIFIER_secp384r1 = new byte[] { 43, -127, 4, 0, 34 };
	private static byte[] OBJECT_IDENTIFIER_secp521r1 = new byte[] { 43, -127, 4, 0, 35 };

	private final OutputStream outputStream;

	public PuttyKeyWriter(final OutputStream outputStream) throws IOException {
		this.outputStream = outputStream;
	}

	public void writePuttyKeyFormat(final PuttyKey puttyKey, final String password) throws Exception {
		final String algorithmName = puttyKey.getAlgorithm();
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

		final String macHash = calculateMacChecksum(passwordBytes, algorithmName, password == null ? "none" : "aes256-cbc", puttyKey.getComment(), publicKeyBytes, privateKeyBytes);

		if (passwordBytes != null) {
			final byte[] puttyKeyEncryptionKey = getPuttyPrivateKeyEncryptionKey(passwordBytes);

			final Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(puttyKeyEncryptionKey, 0, 32, "AES"), new IvParameterSpec(new byte[16])); // initial vector=0

			privateKeyBytes = cipher.doFinal(privateKeyBytes);
		}

		final String publicKeyBase64 = toWrappedBase64(publicKeyBytes, "\r\n");
		final String privateKeyBase64 = toWrappedBase64(privateKeyBytes, "\r\n");

		final StringBuilder content = new StringBuilder();
		content.append("PuTTY-User-Key-File-2: ").append(algorithmName).append("\r\n");
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
		final String algorithmName = puttyKey.getAlgorithm();
		if (PuttyKey.SSH_CIPHER_NAME_RSA.equalsIgnoreCase(algorithmName)) {
			outputStream.write(createRsaBinaryKey(puttyKey));
		} else if (PuttyKey.SSH_CIPHER_NAME_DSA.equalsIgnoreCase(algorithmName)) {
			outputStream.write(createDssBinaryKey(puttyKey));
		} else if (PuttyKey.SSH_CIPHER_NAME_ECDSA_NISTP256.equalsIgnoreCase(algorithmName)) {
			outputStream.write(createEcdsaBinaryKey(puttyKey, OBJECT_IDENTIFIER_secp256r1));
		} else if (PuttyKey.SSH_CIPHER_NAME_ECDSA_NISTP384.equalsIgnoreCase(algorithmName)) {
			outputStream.write(createEcdsaBinaryKey(puttyKey, OBJECT_IDENTIFIER_secp384r1));
		} else if (PuttyKey.SSH_CIPHER_NAME_ECDSA_NISTP521.equalsIgnoreCase(algorithmName)) {
			outputStream.write(createEcdsaBinaryKey(puttyKey, OBJECT_IDENTIFIER_secp521r1));
		} else {
			throw new IllegalArgumentException("Unsupported cipher: " + algorithmName);
		}
	}

	/**
	 * Converts this key into unprotected PEM format (PKCS#1) for OpenSSH keys<br />
	 * <br />
	 * <b>Use with caution, because this key format is not protected by any password</>
	 */
	public void writeUnprotectedPemFormat(final PuttyKey puttyKey) throws Exception {
		final String algorithmName = puttyKey.getAlgorithm();
		if (PuttyKey.SSH_CIPHER_NAME_RSA.equalsIgnoreCase(algorithmName)) {
			outputStream.write("-----BEGIN RSA PRIVATE KEY-----\n".getBytes("ISO-8859-1"));
			outputStream.write(toWrappedBase64(createRsaBinaryKey(puttyKey), "\n").getBytes("ISO-8859-1"));
			outputStream.write("\n".getBytes("ISO-8859-1"));
			outputStream.write("-----END RSA PRIVATE KEY-----\n".getBytes("ISO-8859-1"));
		} else if (PuttyKey.SSH_CIPHER_NAME_DSA.equalsIgnoreCase(algorithmName)) {
			outputStream.write("-----BEGIN DSA PRIVATE KEY-----\n".getBytes("ISO-8859-1"));
			outputStream.write(toWrappedBase64(createDssBinaryKey(puttyKey), "\n").getBytes("ISO-8859-1"));
			outputStream.write("\n".getBytes("ISO-8859-1"));
			outputStream.write("-----END DSA PRIVATE KEY-----\n".getBytes("ISO-8859-1"));
		} else if (PuttyKey.SSH_CIPHER_NAME_ECDSA_NISTP256.equalsIgnoreCase(algorithmName)) {
			outputStream.write("-----BEGIN EC PRIVATE KEY-----\n".getBytes("ISO-8859-1"));
			outputStream.write(toWrappedBase64(createEcdsaBinaryKey(puttyKey, OBJECT_IDENTIFIER_secp256r1), "\n").getBytes("ISO-8859-1"));
			outputStream.write("\n".getBytes("ISO-8859-1"));
			outputStream.write("-----END EC PRIVATE KEY-----\n".getBytes("ISO-8859-1"));
		} else if (PuttyKey.SSH_CIPHER_NAME_ECDSA_NISTP384.equalsIgnoreCase(algorithmName)) {
			outputStream.write("-----BEGIN EC PRIVATE KEY-----\n".getBytes("ISO-8859-1"));
			outputStream.write(toWrappedBase64(createEcdsaBinaryKey(puttyKey, OBJECT_IDENTIFIER_secp384r1), "\n").getBytes("ISO-8859-1"));
			outputStream.write("\n".getBytes("ISO-8859-1"));
			outputStream.write("-----END EC PRIVATE KEY-----\n".getBytes("ISO-8859-1"));
		} else if (PuttyKey.SSH_CIPHER_NAME_ECDSA_NISTP521.equalsIgnoreCase(algorithmName)) {
			outputStream.write("-----BEGIN EC PRIVATE KEY-----\n".getBytes("ISO-8859-1"));
			outputStream.write(toWrappedBase64(createEcdsaBinaryKey(puttyKey, OBJECT_IDENTIFIER_secp521r1), "\n").getBytes("ISO-8859-1"));
			outputStream.write("\n".getBytes("ISO-8859-1"));
			outputStream.write("-----END EC PRIVATE KEY-----\n".getBytes("ISO-8859-1"));
		} else {
			throw new IllegalArgumentException("Unsupported cipher: " + algorithmName);
		}
	}

	private byte[] createRsaBinaryKey(final PuttyKey puttyKey) throws Exception {
		final RSAPrivateCrtKey privateKey = ((RSAPrivateCrtKey) puttyKey.getKeyPair().getPrivate());

		return createDerTagData(DER_TAG_SEQUENCE,
				createDerTagData(DER_TAG_INTEGER, BigInteger.ZERO.toByteArray()),
				createDerTagData(DER_TAG_INTEGER, privateKey.getModulus().toByteArray()),
				createDerTagData(DER_TAG_INTEGER, privateKey.getPublicExponent().toByteArray()),
				createDerTagData(DER_TAG_INTEGER, privateKey.getPrivateExponent().toByteArray()),
				createDerTagData(DER_TAG_INTEGER, privateKey.getPrimeP().toByteArray()),
				createDerTagData(DER_TAG_INTEGER, privateKey.getPrimeQ().toByteArray()),
				createDerTagData(DER_TAG_INTEGER, privateKey.getPrimeExponentP().toByteArray()),
				createDerTagData(DER_TAG_INTEGER, privateKey.getPrimeExponentQ().toByteArray()),
				createDerTagData(DER_TAG_INTEGER, privateKey.getCrtCoefficient().toByteArray())
				);
	}

	private byte[] createDssBinaryKey(final PuttyKey puttyKey) throws Exception {
		final DSAPublicKey publicKey = ((DSAPublicKey) puttyKey.getKeyPair().getPublic());
		final DSAPrivateKey privateKey = ((DSAPrivateKey) puttyKey.getKeyPair().getPrivate());

		return createDerTagData(DER_TAG_SEQUENCE,
				createDerTagData(DER_TAG_INTEGER, BigInteger.ZERO.toByteArray()),
				createDerTagData(DER_TAG_INTEGER, privateKey.getParams().getP().toByteArray()),
				createDerTagData(DER_TAG_INTEGER, privateKey.getParams().getQ().toByteArray()),
				createDerTagData(DER_TAG_INTEGER, privateKey.getParams().getG().toByteArray()),
				createDerTagData(DER_TAG_INTEGER, publicKey.getY().toByteArray()),
				createDerTagData(DER_TAG_INTEGER, privateKey.getX().toByteArray())
				);
	}

	private byte[] createEcdsaBinaryKey(final PuttyKey puttyKey, byte[] oidKey) throws Exception {
		final ECPrivateKey privateKey = ((ECPrivateKey) puttyKey.getKeyPair().getPrivate());
		final ECPublicKey publicKey = ((ECPublicKey) puttyKey.getKeyPair().getPublic());
		
		return createDerTagData(DER_TAG_SEQUENCE,
				createDerTagData(DER_TAG_INTEGER, BigInteger.ONE.toByteArray()),
				createDerTagData(DER_TAG_OCTET_STRING, privateKey.getS().toByteArray()),
				createDerTagData(DER_TAG_CONTEXT_SPECIFIC_0, createDerTagData(DER_TAG_OBJECT, oidKey)),
				createDerTagData(DER_TAG_CONTEXT_SPECIFIC_1, createDerTagData(DER_TAG_BIT_STRING,
						joinByteArrays(
								new byte[] {0, 4},
								publicKey.getW().getAffineX().toByteArray(),
								publicKey.getW().getAffineY().toByteArray()))
						)
				);
	}

	/**
	 * Converts byte array to base64 with 64 chars per line
	 */
	private static String toWrappedBase64(final byte[] byteArray, final String lineBreak) {
		return Base64.getMimeEncoder(64, lineBreak.getBytes(Charset.forName("ISO-8859-1"))).encodeToString(byteArray);
	}

	private byte[] joinByteArrays(final byte[]... arrays) throws Exception {
		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		for (final byte[] array : arrays) {
			out.write(array);
		}
		return out.toByteArray();
	}

	private static byte[] createDerTagData(final int derTagId, final byte[]... derDataItems) throws IOException {
		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		out.write(derTagId);
		int dataItemsLength = 0;
		for (final byte[] dataItem : derDataItems) {
			dataItemsLength += dataItem.length;
		}
		if (dataItemsLength < 0x80) {
			out.write(dataItemsLength);
		} else {
			final int bytes = getByteEncodedLength(dataItemsLength);
			out.write(0x80 | bytes);
			for (int i = bytes - 1; i >= 0; i--) {
				out.write((dataItemsLength >> (8 * i)) & 0xFF);
			}
		}
		for (final byte[] dataItem : derDataItems) {
			out.write(dataItem);
		}
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
