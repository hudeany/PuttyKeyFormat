package de.soderer.utilities;

import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;

/**
 * This helper converts a PuttyKey into the OpenSSH key format.<br />
 * <br />
 * This function is depending on the BouncyCastle crypto library.<br />
 * Therefore it is kept in an extra class.
 */
public class PuttyKeyOpenSshHelper {
	/**
	 * Write password protected pem file (PKCS#8)<br />
	 * keyEncryptionCipherName:<br />
	 *   default is "AES-128-CBC"<br />
	 *   other value may be "DES-EDE3-CBC"<br />
	 */
	public static String writeKeyPairToProtectedPrivateOpenSshKey(final KeyPair keyPair, String keyEncryptionCipherName, final String exportedKeyPassword) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		if (keyEncryptionCipherName == null || "".equals(keyEncryptionCipherName.trim())) {
			keyEncryptionCipherName = "AES-128-CBC";
		}

		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		try (final JcaPEMWriter jcaPEMWriter = new JcaPEMWriter(new OutputStreamWriter(outputStream, StandardCharsets.US_ASCII))) {
			if (exportedKeyPassword != null) {
				final PEMEncryptor pemEncryptor = new JcePEMEncryptorBuilder(keyEncryptionCipherName).build(exportedKeyPassword.toCharArray());
				final JcaMiscPEMGenerator pemGenerator = new JcaMiscPEMGenerator(keyPair.getPrivate(), pemEncryptor);
				jcaPEMWriter.writeObject(pemGenerator);
			} else {
				jcaPEMWriter.writeObject(keyPair.getPrivate());
			}

			jcaPEMWriter.flush();
		}
		return new String(outputStream.toByteArray(), "UTF-8");
	}
}
