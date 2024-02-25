package cc.walle.neopgp;

import static org.junit.Assert.*;
import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.AIDUtil;
import com.licel.jcardsim.utils.ByteUtil;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import javax.smartcardio.ResponseAPDU;

public abstract class JcardsimTestCase {

	Simulator simulator;
	//AID appletAID = AIDUtil.create("d27600012401");
	AID appletAID = AIDUtil.create("d276000124010304ffff000000000000");

   	public JcardsimTestCase() {
		byte[] buf = new byte[32];
		buf[0] = appletAID.getBytes(buf, (short)1);

		simulator = new Simulator();
		simulator.installApplet(appletAID, NeoPGPApplet.class, buf, (short)0, (byte)(buf[0] + 1));
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
