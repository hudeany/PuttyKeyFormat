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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;

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
	private static final String AES128_PemEncryptionMethodName = "AES-128-CBC";
	private static final String TripleDES_PemEncryptionMethodName = "DES-EDE3-CBC";

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
		privateKeyBytes = addSecurePadding(privateKeyBytes, 16);

		final String macHash = calculateMacChecksum(passwordBytes, algorithmName, password == null ? "none" : "aes256-cbc", puttyKey.getComment(), publicKeyBytes, privateKeyBytes);

		if (passwordBytes != null) {
			final byte[] puttyKeyEncryptionKey = stretchPasswordForPutty(passwordBytes);

			final Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(puttyKeyEncryptionKey, 0, 32, "AES"), new IvParameterSpec(new byte[16])); // initial vector=0

			privateKeyBytes = cipher.doFinal(privateKeyBytes);
		}

		final String publicKeyBase64 = toWrappedBase64(publicKeyBytes, 64, "\r\n");
		final String privateKeyBase64 = toWrappedBase64(privateKeyBytes, 64, "\r\n");

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

	private static byte[] stretchPasswordForPutty(final byte[] passwordByteArray) throws NoSuchAlgorithmException {
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
			outputStream.write(createEcdsaBinaryKey(puttyKey, OID.SECP256R1_ARRAY));
		} else if (PuttyKey.SSH_CIPHER_NAME_ECDSA_NISTP384.equalsIgnoreCase(algorithmName)) {
			outputStream.write(createEcdsaBinaryKey(puttyKey, OID.SECP384R1_ARRAY));
		} else if (PuttyKey.SSH_CIPHER_NAME_ECDSA_NISTP521.equalsIgnoreCase(algorithmName)) {
			outputStream.write(createEcdsaBinaryKey(puttyKey, OID.SECP521R1_ARRAY));
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
			outputStream.write(toWrappedBase64(createRsaBinaryKey(puttyKey), 64, "\n").getBytes("ISO-8859-1"));
			outputStream.write("\n-----END RSA PRIVATE KEY-----\n".getBytes("ISO-8859-1"));
		} else if (PuttyKey.SSH_CIPHER_NAME_DSA.equalsIgnoreCase(algorithmName)) {
			outputStream.write("-----BEGIN DSA PRIVATE KEY-----\n".getBytes("ISO-8859-1"));
			outputStream.write(toWrappedBase64(createDssBinaryKey(puttyKey), 64, "\n").getBytes("ISO-8859-1"));
			outputStream.write("\n-----END DSA PRIVATE KEY-----\n".getBytes("ISO-8859-1"));
		} else if (PuttyKey.SSH_CIPHER_NAME_ECDSA_NISTP256.equalsIgnoreCase(algorithmName)) {
			outputStream.write("-----BEGIN EC PRIVATE KEY-----\n".getBytes("ISO-8859-1"));
			outputStream.write(toWrappedBase64(createEcdsaBinaryKey(puttyKey, OID.SECP256R1_ARRAY), 64, "\n").getBytes("ISO-8859-1"));
			outputStream.write("\n-----END EC PRIVATE KEY-----\n".getBytes("ISO-8859-1"));
		} else if (PuttyKey.SSH_CIPHER_NAME_ECDSA_NISTP384.equalsIgnoreCase(algorithmName)) {
			outputStream.write("-----BEGIN EC PRIVATE KEY-----\n".getBytes("ISO-8859-1"));
			outputStream.write(toWrappedBase64(createEcdsaBinaryKey(puttyKey, OID.SECP384R1_ARRAY), 64, "\n").getBytes("ISO-8859-1"));
			outputStream.write("\n-----END EC PRIVATE KEY-----\n".getBytes("ISO-8859-1"));
		} else if (PuttyKey.SSH_CIPHER_NAME_ECDSA_NISTP521.equalsIgnoreCase(algorithmName)) {
			outputStream.write("-----BEGIN EC PRIVATE KEY-----\n".getBytes("ISO-8859-1"));
			outputStream.write(toWrappedBase64(createEcdsaBinaryKey(puttyKey, OID.SECP521R1_ARRAY), 64, "\n").getBytes("ISO-8859-1"));
			outputStream.write("\n-----END EC PRIVATE KEY-----\n".getBytes("ISO-8859-1"));
		} else {
			throw new IllegalArgumentException("Unsupported cipher: " + algorithmName);
		}
	}

	/**
	 * Converts this key into protected PEM format (PKCS#8) for OpenSSH keys<br />
	 * Using default encryption method "AES-128-CBC"<br />
	 * This format includes private and public key data and is accepted by PuTTY's key import<br />
	 */
	public void writeProtectedPemFormat(final PuttyKey puttyKey, final String exportedKeyPassword) throws Exception {
		writeProtectedPemFormat(puttyKey, null, exportedKeyPassword);
	}

	/**
	 * Converts this key into protected PEM format (PKCS#8) for OpenSSH keys<br />
	 * This format includes private and public key data and is accepted by PuTTY's key import<br />
	 * <br />
	 * keyEncryptionCipherName:<br />
	 *   default is "AES-128-CBC"<br />
	 *   other value may be "DES-EDE3-CBC"<br />
	 */
	public void writeProtectedPemFormat(final PuttyKey puttyKey, String keyEncryptionCipherName, final String exportedKeyPassword) throws Exception {
		if (keyEncryptionCipherName == null || "".equals(keyEncryptionCipherName.trim())) {
			keyEncryptionCipherName = AES128_PemEncryptionMethodName;
		}

		if (!AES128_PemEncryptionMethodName.equalsIgnoreCase(keyEncryptionCipherName) && !TripleDES_PemEncryptionMethodName.equalsIgnoreCase(keyEncryptionCipherName)) {
			throw new Exception("Unknown key encryption cipher: " + keyEncryptionCipherName);
		}

		if (exportedKeyPassword == null || "".equals(exportedKeyPassword)) {
			throw new Exception("Mandatory password is missing");
		}

		String keyTypeName;
		byte[] keyData;
		final String algorithmName = puttyKey.getAlgorithm();
		if (PuttyKey.SSH_CIPHER_NAME_RSA.equalsIgnoreCase(algorithmName)) {
			keyTypeName = "RSA PRIVATE KEY";
			keyData = createRsaBinaryKey(puttyKey);
		} else if (PuttyKey.SSH_CIPHER_NAME_DSA.equalsIgnoreCase(algorithmName)) {
			keyTypeName = "DSA PRIVATE KEY";
			keyData = createDssBinaryKey(puttyKey);
		} else if (PuttyKey.SSH_CIPHER_NAME_ECDSA_NISTP256.equalsIgnoreCase(algorithmName)) {
			keyTypeName = "EC PRIVATE KEY";
			keyData = createEcdsaBinaryKey(puttyKey, OID.SECP256R1_ARRAY);
		} else if (PuttyKey.SSH_CIPHER_NAME_ECDSA_NISTP384.equalsIgnoreCase(algorithmName)) {
			keyTypeName = "EC PRIVATE KEY";
			keyData = createEcdsaBinaryKey(puttyKey, OID.SECP384R1_ARRAY);
		} else if (PuttyKey.SSH_CIPHER_NAME_ECDSA_NISTP521.equalsIgnoreCase(algorithmName)) {
			keyTypeName = "EC PRIVATE KEY";
			keyData = createEcdsaBinaryKey(puttyKey, OID.SECP521R1_ARRAY);
		} else {
			throw new IllegalArgumentException("Unsupported cipher: " + algorithmName);
		}

		final Map<String, String> headers = new LinkedHashMap<>();

		final SecureRandom rnd = new SecureRandom();
		final Cipher cipher;
		final String ivString;
		if (TripleDES_PemEncryptionMethodName.equalsIgnoreCase(keyEncryptionCipherName)) {
			final byte[] iv = new byte[8];
			rnd.nextBytes(iv);
			ivString = toHexString(iv);
			cipher = Cipher.getInstance("DESede/CBC/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(stretchPasswordForOpenSsl(exportedKeyPassword, iv, 8, 24), "DESede"), new IvParameterSpec(iv));
			keyData = addSecurePadding(keyData, 16);
		} else if (AES128_PemEncryptionMethodName.equalsIgnoreCase(keyEncryptionCipherName)) {
			final byte[] iv = new byte[16];
			rnd.nextBytes(iv);
			ivString = toHexString(iv);
			cipher = Cipher.getInstance("AES/CBC/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(stretchPasswordForOpenSsl(exportedKeyPassword, iv, 8, 16), "AES"), new IvParameterSpec(iv));
			keyData = addSecurePadding(keyData, 16);
		} else {
			throw new Exception("Unknown key encryption cipher: " + keyEncryptionCipherName);
		}
		headers.put("Proc-Type", "4,ENCRYPTED");
		headers.put("DEK-Info", keyEncryptionCipherName.toUpperCase() + "," + ivString);

		final byte[] encryptedKeyData = cipher.doFinal(keyData);

		outputStream.write(("-----BEGIN " + keyTypeName + "-----\n").getBytes("UTF-8"));
		outputStream.write(getPemHeaderLines(headers, 76).getBytes("UTF-8"));
		outputStream.write(toWrappedBase64(encryptedKeyData, 76, "\n").getBytes("UTF-8"));
		outputStream.write(("\n-----END " + keyTypeName + "-----\n").getBytes("UTF-8"));
	}

	private static String getPemHeaderLines(final Map<String, String> headers, final int maxLineLimit) {
		final StringBuilder headerBuilder = new StringBuilder();
		if (!headers.isEmpty()) {
			for (final Entry<String, String> entry : headers.entrySet()) {
				headerBuilder.append(entry.getKey() + ": ");
				if ((entry.getKey().length() + entry.getValue().length() + 2) > maxLineLimit) {
					int offset = Math.max(maxLineLimit - entry.getKey().length() - 2, 0);
					headerBuilder.append(entry.getValue().substring(0, offset) + "\\" + "\n");
					for (; offset < entry.getValue().length(); offset += maxLineLimit) {
						if ((offset + maxLineLimit) >= entry.getValue().length()) {
							headerBuilder.append(entry.getValue().substring(offset) + "\n");
						} else {
							headerBuilder.append(entry.getValue().substring(offset, offset + maxLineLimit) + "\\" + "\n");
						}
					}
				} else {
					headerBuilder.append(entry.getValue() + "\n");
				}
			}

			headerBuilder.append("\n");
		}
		return headerBuilder.toString();
	}

	private static byte[] stretchPasswordForOpenSsl(final String password, final byte[] iv, final int usingIvSize, final int keySize) throws Exception {
		final byte[] passphraseBytes = password.getBytes("ISO-8859-1");
		final MessageDigest hash = MessageDigest.getInstance("MD5");
		final byte[] key = new byte[keySize];
		int hashesSize = keySize & 0XFFFFFFF0;

		if ((keySize & 0XF) != 0) {
			hashesSize += 0x10;
		}

		final byte[] hashes = new byte[hashesSize];
		byte[] previous;
		for (int index = 0; (index + 0x10) <= hashes.length; hash.update(previous, 0, previous.length)) {
			hash.update(passphraseBytes, 0, passphraseBytes.length);
			hash.update(iv, 0, usingIvSize);
			previous = hash.digest();
			System.arraycopy(previous, 0, hashes, index, previous.length);
			index += previous.length;
		}

		System.arraycopy(hashes, 0, key, 0, key.length);
		return key;
	}

	private static byte[] createRsaBinaryKey(final PuttyKey puttyKey) throws Exception {
		final RSAPrivateCrtKey privateKey = ((RSAPrivateCrtKey) puttyKey.getKeyPair().getPrivate());

		return Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_SEQUENCE,
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, BigInteger.ZERO.toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getModulus().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getPublicExponent().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getPrivateExponent().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getPrimeP().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getPrimeQ().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getPrimeExponentP().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getPrimeExponentQ().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getCrtCoefficient().toByteArray())
				);
	}

	private static byte[] createDssBinaryKey(final PuttyKey puttyKey) throws Exception {
		final DSAPublicKey publicKey = ((DSAPublicKey) puttyKey.getKeyPair().getPublic());
		final DSAPrivateKey privateKey = ((DSAPrivateKey) puttyKey.getKeyPair().getPrivate());

		return Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_SEQUENCE,
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, BigInteger.ZERO.toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getParams().getP().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getParams().getQ().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getParams().getG().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, publicKey.getY().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, privateKey.getX().toByteArray())
				);
	}

	private static byte[] createEcdsaBinaryKey(final PuttyKey puttyKey, final byte[] oidKey) throws Exception {
		final ECPrivateKey privateKey = ((ECPrivateKey) puttyKey.getKeyPair().getPrivate());
		final ECPublicKey publicKey = ((ECPublicKey) puttyKey.getKeyPair().getPublic());

		return Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_SEQUENCE,
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_INTEGER, BigInteger.ONE.toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_OCTET_STRING, privateKey.getS().toByteArray()),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_CONTEXT_SPECIFIC_0, Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_OBJECT, oidKey)),
				Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_CONTEXT_SPECIFIC_1, Asn1Codec.createDerTagData(Asn1Codec.DER_TAG_BIT_STRING,
						joinByteArrays(
								new byte[] {0, 4},
								publicKey.getW().getAffineX().toByteArray(),
								publicKey.getW().getAffineY().toByteArray()))
						)
				);
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

	private static byte[] addSecurePadding(byte[] data, final int paddingSize) {
		if (data.length % paddingSize != 0) {
			final byte[] dataPadded = new byte[((data.length / paddingSize) + 1) * paddingSize];
			for (int i = 0; i < data.length; i++) {
				dataPadded[i] = data[i];
			}
			final byte[] randomArray = new byte[dataPadded.length - data.length];
			new SecureRandom().nextBytes(randomArray);
			for (int i = 0; i < randomArray.length; i++) {
				dataPadded[data.length + i] = randomArray[i];
			}
			data = dataPadded;
		}
		return data;
	}

	/**
	 * Converts byte array to base64 with linebreaks
	 */
	private static String toWrappedBase64(final byte[] byteArray, final int maxLineLength, final String lineBreak) {
		return Base64.getMimeEncoder(maxLineLength, lineBreak.getBytes(Charset.forName("ISO-8859-1"))).encodeToString(byteArray);
	}

	private static byte[] joinByteArrays(final byte[]... arrays) throws Exception {
		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		for (final byte[] array : arrays) {
			out.write(array);
		}
		return out.toByteArray();
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
