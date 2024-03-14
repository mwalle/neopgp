// SPDX-License-Identifier: GPL-3.0-or-later
package cc.walle.neopgp;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public abstract class NeoByteArray {
	byte[] data = null;
	byte[] defaultValue = null;

	NeoByteArray(short maxLength) {
		data = new byte[maxLength];
	}

	NeoByteArray(short maxLength, byte[] defaultValue) {
		this(maxLength);
		if (defaultValue.length > data.length)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		this.defaultValue = defaultValue;
	}

	abstract short getLength();

	public short setNonAtomic(byte[] buf, short off, short len) {
		if (len > data.length)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		Util.arrayCopyNonAtomic(buf, off, data, (short)0, len);
		return (short)(off + len);
	}

	public short set(byte[] buf, short off, short len) {
		JCSystem.beginTransaction();
		off = setNonAtomic(buf, off, len);
		JCSystem.commitTransaction();
		return off;
	}

	public short get(byte[] buf, short off) {
		return Util.arrayCopyNonAtomic(data, (short)0, buf, off, getLength());
	}

	public void clear() {
		short off = 0;
		if (defaultValue != null)
			off = Util.arrayCopyNonAtomic(defaultValue, (short)0, data, off, (short)defaultValue.length);
		if (off < data.length)
			Util.arrayFillNonAtomic(data, off, (short)(data.length - off), (byte)0);
	}
}
