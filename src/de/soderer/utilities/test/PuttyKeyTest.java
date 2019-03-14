package de.soderer.utilities.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import de.soderer.utilities.PuttyKey;
import de.soderer.utilities.PuttyKeyReader;
import de.soderer.utilities.PuttyKeyWriter;

public class PuttyKeyTest {
	public void test() throws Exception {
		final PuttyKey puttyKey = new PuttyKey("TestKey", 2048);

		final ByteArrayOutputStream output = new ByteArrayOutputStream();
		try (PuttyKeyWriter puttyKeyWriter = new PuttyKeyWriter(output)) {
			puttyKeyWriter.writePuttyKeyFormat(puttyKey, "password");
		}

		PuttyKey puttyKey2;
		try (PuttyKeyReader puttyKeyReader = new PuttyKeyReader(new ByteArrayInputStream(output.toByteArray()))) {
			puttyKeyReader.setPassword("password".toCharArray());
			puttyKey2 = puttyKeyReader.readKey();
		}

		final String authKey = puttyKey2.encodePublicKeyForAuthorizedKeys();
		if (authKey == null || authKey.length() == 0) {
			throw new Exception();
		}

		final ByteArrayOutputStream output2 = new ByteArrayOutputStream();
		try (PuttyKeyWriter puttyKeyWriter = new PuttyKeyWriter(output2)) {
			puttyKeyWriter.writeUnprotectedPemFormat(puttyKey2);
		}
		if (output2.toByteArray() == null || output2.toByteArray().length == 0) {
			throw new Exception();
		}

		final ByteArrayOutputStream output3 = new ByteArrayOutputStream();
		try (PuttyKeyWriter puttyKeyWriter = new PuttyKeyWriter(output3)) {
			puttyKeyWriter.writeProtectedPemFormat(puttyKey, "DES-EDE3-CBC", "password");
		}
		if (output3.toByteArray() == null || output3.toByteArray().length == 0) {
			throw new Exception();
		}
	}
}
