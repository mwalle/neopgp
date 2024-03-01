// SPDX-License-Identifier: GPL-3.0-or-later
package javacardx.framework.tlv;

import static org.junit.Assert.*;
import org.junit.Test;
import javacardx.framework.tlv.TLVException;

public class ConstructedBERTLVTest {
	static final byte[] BER_TAGS = { (byte)0x02, (byte)0x03, (byte)0x7f, (byte)0x32, 0x04 };

	byte[] constructedTLV = {
		(byte)0xde, (byte)0xad,
		(byte)0x30, (byte)0x0c,
		(byte)0x03, (byte)0x02, (byte)0x11, (byte)0x22,
		(byte)0x03, (byte)0x03, (byte)0x11, (byte)0x22, (byte)0x33,
		(byte)0x02, (byte)0x02, (byte)0x11, (byte)0x22,
	};

	byte[] constructedTwoByteTagTLV = {
		(byte)0x31, (byte)0x09,
		(byte)0x7f, (byte)0x32, (byte)0x01, (byte)0x11,
		(byte)0x03, (byte)0x03, (byte)0x11, (byte)0x22, (byte)0x33,
	};

	@Test
	public void constructedTLVLength() {
		assertEquals(12, ConstructedBERTLV.getLength(constructedTLV, (short)2));
	}

	@Test
	public void constructedTLVTags() {
		assertEquals(4, ConstructedBERTLV.find(constructedTLV, (short)2, BER_TAGS, (short)1));
		assertEquals(8, ConstructedBERTLV.findNext(constructedTLV, (short)2, (short)4, BER_TAGS, (short)1));
		assertEquals(13, ConstructedBERTLV.findNext(constructedTLV, (short)2, (short)8, BER_TAGS, (short)0));
	}

	@Test
	public void constructedTLVTagNotFound() {
		assertEquals(-1, ConstructedBERTLV.find(constructedTLV, (short)2, BER_TAGS, (short)4));
	}

	@Test
	public void constructedTLVSkippedTag() {
		assertEquals(4, ConstructedBERTLV.find(constructedTLV, (short)2, BER_TAGS, (short)1));
		assertEquals(13, ConstructedBERTLV.findNext(constructedTLV, (short)2, (short)4, BER_TAGS, (short)0));
	}

	@Test
	public void constructedTwoByteTagTLV() {
		assertEquals(2, ConstructedBERTLV.find(constructedTwoByteTagTLV, (short)0, BER_TAGS, (short)2));
		assertEquals(6, ConstructedBERTLV.findNext(constructedTwoByteTagTLV, (short)0, (short)2, BER_TAGS, (short)1));
	}
}
