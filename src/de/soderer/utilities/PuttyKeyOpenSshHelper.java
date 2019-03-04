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
	public static String convertPuttyKeyToProtectedPrivateOpenSshKey(final PuttyKey puttyKey, final String exportedKeyPassword) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final KeyPair keyPair = puttyKey.getKeyPair();
		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		try (final JcaPEMWriter jcaPEMWriter = new JcaPEMWriter(new OutputStreamWriter(outputStream, StandardCharsets.US_ASCII))) {
			if (exportedKeyPassword != null) {
				final PEMEncryptor pemEncryptor = new JcePEMEncryptorBuilder("AES-128-CBC").build(exportedKeyPassword.toCharArray());
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
