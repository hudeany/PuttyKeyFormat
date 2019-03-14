package de.soderer.utilities;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.IOException;
import java.math.BigInteger;

/**
 * Encoder / Decoder for the ASN.1 format
 */
public class Asn1Codec {
	/**
	 * ASN.1 "INTEGER" (0x02 = 2)
	 */
	public static final int DER_TAG_INTEGER = 0x02;

	/**
	 * ASN.1 "BIT STRING" (0x03 = 3)
	 */
	public static final int DER_TAG_BIT_STRING = 0x03;

	/**
	 * ASN.1 "OCTET STRING" (0x04 = 4)
	 */
	public static final int DER_TAG_OCTET_STRING = 0x04;

	/**
	 * ASN.1 "OBJECT" (0x06 = 6)
	 */
	public static final int DER_TAG_OBJECT = 0x06;

	/**
	 * ASN.1 "SEQUENCE" (0x30 = 48)
	 */
	public static final int DER_TAG_SEQUENCE = 0x30;

	/**
	 * ASN.1 CONTEXT SPECIFIC "cont [ 0 ]" (0xA0 = -96 = unsigned 160)
	 */
	public static final int DER_TAG_CONTEXT_SPECIFIC_0 = 0xA0;

	/**
	 * ASN.1 CONTEXT SPECIFIC "cont [ 1 ]" (0xA1 = -95 = unsigned 161)
	 */
	public static final int DER_TAG_CONTEXT_SPECIFIC_1 = 0xA1;

	public static byte[] getAsnEncodedInteger(final long value) throws Exception {
		if (value < 0) {
			throw new Exception("Minimum ASN.1 encoded Integer underrun");
		} else if (value < 0x80) {
			return new byte[] { (byte) value };
		} else {
			final ByteArrayOutputStream out = new ByteArrayOutputStream();
			byte[] data = BigInteger.valueOf(value).toByteArray();
			if (data[0] == 0) {
				// Removed the obsolete sign bit, which caused an additional byte
				final byte[] tmp = new byte[data.length - 1];
				System.arraycopy(data, 1, tmp, 0, tmp.length);
				data = tmp;
			}
			if (data.length >= 0x80) {
				throw new Exception("Maximum ASN.1 encoded Integer exceeded");
			}
			out.write(0x80 | data.length);
			out.write(data);
			return out.toByteArray();
		}
	}

	public static BigInteger parseAsnEncodedInteger(final byte[] data, final int offset) throws Exception {
		try {
			final DataInput blockDataInput = new DataInputStream(new ByteArrayInputStream(data));
			blockDataInput.skipBytes(offset - 1);

			final int nextBlockSize = blockDataInput.readInt();
			if (nextBlockSize <= 0 || nextBlockSize > 513) {
				throw new Exception("Key blocksize error");
			}
			final byte[] nextBlock = new byte[nextBlockSize];
			blockDataInput.readFully(nextBlock);
			return new BigInteger(nextBlock);
		} catch (final IOException e) {
			throw new Exception("Key block read error", e);
		}
	}

	public static byte[] createDerTagData(final int derTagId, final byte[]... derDataItems) throws IOException {
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
}
