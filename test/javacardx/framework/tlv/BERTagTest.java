// SPDX-License-Identifier: GPL-3.0-or-later
package javacardx.framework.tlv;

import static org.junit.Assert.*;
import org.junit.Test;
import javacardx.framework.tlv.BERTag;
import javacardx.framework.tlv.TLVException;

public class BERTagTest {
	byte[] oneByteTag = { (byte)0xde, (byte)0xad, (byte)0x1e };
	byte[] twoByteTag = { (byte)0xde, (byte)0xad, (byte)0xff, (byte)0x7f };
	byte[] invalidTwoByteTag = { (byte)0xde, (byte)0xad, (byte)0x1f, (byte)0x1e };
	byte[] threeByteTag = { (byte)0xde, (byte)0xad, (byte)0x1f, (byte)0xff, (byte)0x7f };

	@Test
	public void oneByteTagSize() {
		assertEquals(1, BERTag.size(oneByteTag, (short)2));
	}

	@Test
	public void oneByteTagNumber() {
		assertEquals(30, BERTag.tagNumber(oneByteTag, (short)2));
	}

	@Test
	public void twoByteTagSize() {
		assertEquals(2, BERTag.size(twoByteTag, (short)2));
	}

	@Test
	public void twoByteTagNumber() {
		assertEquals(127, BERTag.tagNumber(twoByteTag, (short)2));
	}

	@Test
	public void invalidTwoByteTagNumber() {
		TLVException e = assertThrows(TLVException.class,
			() -> BERTag.tagNumber(invalidTwoByteTag, (short)2));
		assertEquals(TLVException.MALFORMED_TAG, e.getReason());
	}

	@Test
	public void threeByteTagNumber() {
		TLVException e = assertThrows(TLVException.class,
			() -> BERTag.tagNumber(threeByteTag, (short)2));
		assertEquals(TLVException.ILLEGAL_SIZE, e.getReason());
	}

	@Test
	public void primitiveTag() {
		assertFalse(BERTag.isConstructed(oneByteTag, (short)2));
	}

	@Test
	public void constructedTag() {
		assertTrue(BERTag.isConstructed(twoByteTag, (short)2));
	}

	@Test
	public void universalTagClass() {
		assertEquals(BERTag.BER_TAG_CLASS_MASK_UNIVERSAL, BERTag.tagClass(oneByteTag, (short)2));
	}

	@Test
	public void privateTagClass() {
		assertEquals(BERTag.BER_TAG_CLASS_MASK_PRIVATE, BERTag.tagClass(twoByteTag, (short)2));
	}
}
