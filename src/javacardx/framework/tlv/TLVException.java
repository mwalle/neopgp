// SPDX-License-Identifier: GPL-3.0-or-later
package javacardx.framework.tlv;

import javacard.framework.CardRuntimeException;

public class TLVException extends CardRuntimeException {
	public static final short INVALID_PARAM = 1;
	public static final short ILLEGAL_SIZE = 2;
	public static final short EMPTY_TAG = 3;
	public static final short EMPTY_TLV = 4;
	public static final short MALFORMED_TAG = 5;
	public static final short MALFORMED_TLV = 6;
	public static final short INSUFFICIENT_STORAGE = 7;
	public static final short TAG_SIZE_GREATER_THAN_127 = 8;
	public static final short TAG_NUMBER_GREATER_THAN_32767 = 9;
	public static final short TLV_SIZE_GREATER_THAN_32767 = 10;
	public static final short TLV_LENGTH_GREATER_THAN_32767 = 11;

	private static TLVException theTLVException;

	public TLVException(short reason) {
		super(reason);
	}

	public static void throwIt(short reason) {
		if (theTLVException == null)
			theTLVException = new TLVException((short)0);
		theTLVException.setReason(reason);
		throw theTLVException;
	}
}
