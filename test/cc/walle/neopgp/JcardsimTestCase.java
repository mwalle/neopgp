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
	//AID appletAID = AIDUtil.create("d27600012401");
	AID appletAID = AIDUtil.create("d276000124010304ffff000000000000");
	byte[] info = ByteUtil.byteArray("00");
	byte[] params = ByteUtil.byteArray("0001");

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

	public void admin() {
		assertResponseOK("00200083083132333435363738");
	}

	public ResponseAPDU transmit(String command) {
		return new ResponseAPDU(simulator.transmitCommand(ByteUtil.byteArray(command)));
	}

	public void assertResponseOK(String command) {
		assertEquals(ISO7816.SW_NO_ERROR & 0xffff, transmit(command).getSW());
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
