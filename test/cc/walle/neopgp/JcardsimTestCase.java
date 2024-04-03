package cc.walle.neopgp;

import static org.junit.Assert.*;
import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.AIDUtil;
import com.licel.jcardsim.utils.ByteUtil;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.Util;
import javax.smartcardio.ResponseAPDU;

public abstract class JcardsimTestCase {

	Simulator simulator;
	AID appletAID = AIDUtil.create("D2760001240103040010000000000000");
	byte[] info = ByteUtil.byteArray("00");
	byte[] params = ByteUtil.byteArray("0009");

   	public JcardsimTestCase() {
		byte[] buf = new byte[32];
		short off = 0;
		byte len;

		/* aid */
		len = appletAID.getBytes(buf, (short)1);
		buf[off++] = len;
		off += len;

		/* info */
		buf[off++] = (byte)info.length;
		off = Util.arrayCopyNonAtomic(info, (short)0, buf, off, (short)info.length);

		/* params */
		buf[off++] = (byte)params.length;
		off = Util.arrayCopyNonAtomic(params, (short)0, buf, off, (short)params.length);

		simulator = new Simulator();
		simulator.installApplet(appletAID, NeoPGPApplet.class, buf, (short)0, (byte)off);
		simulator.selectApplet(appletAID);
	}

	/**
	 * Sends the default admin PIN.
	 */
	public void admin() {
		assertResponseOK("00200083 08 3132333435363738");
	}

	/**
	 * Changes the signature key to RSA-2048.
	 *
	 * @param keyRef Key ID, 1 for SIG, 2 for DEC, 3 for AUT key.
	 */
	public void changeKey(int keyRef, int keyType) {
		String cmd, typeAndOID;

		switch (keyRef) {
		case NeoKey.SIGNATURE_KEY:
			cmd = "00DA00C1";
			break;
		case NeoKey.DECRYPTION_KEY:
			cmd = "00DA00C2";
			break;
		case NeoKey.AUTHENTICATION_KEY:
			cmd = "00DA00C3";
			break;
		default:
			throw new RuntimeException();
		}

		switch (keyType) {
		case NeoKey.ALGORITHM_ID_RSA:
			typeAndOID = "06 010800001100";
			break;
		case NeoKey.ALGORITHM_ID_ECDH:
			typeAndOID = "0A 122A8648CE3D030107FF";
			break;
		case NeoKey.ALGORITHM_ID_ECDSA:
			typeAndOID = "0A 132A8648CE3D030107FF";
			break;
		default:
			throw new RuntimeException();
		}

		assertResponseOK(cmd + typeAndOID);
	}

	public ResponseAPDU transmit(String command) {
		return new ResponseAPDU(simulator.transmitCommand(ByteUtil.byteArray(command)));
	}

	public void assertResponseOK(String command) {
		int status = (short)transmit(command).getSW() & 0xffff;

		assertTrue(String.format("Status was %04X", status),
			(ISO7816.SW_NO_ERROR & 0xffff) == status);
	}

	public void assertResponseStatus(int expected, String command) {
		assertEquals(expected & 0xffff, transmit(command).getSW());
	}

	public void assertResponseData(String expected, String command) {
		ResponseAPDU res = transmit(command);
		assertEquals(ISO7816.SW_NO_ERROR & 0xffff, res.getSW());
		assertEquals(expected, ByteUtil.hexString(res.getData()));
	}
}
