// SPDX-License-Identifier: GPL-3.0-or-later
package cc.walle.neopgp;

import static org.junit.Assert.*;
import javax.smartcardio.ResponseAPDU;
import javacard.framework.ISO7816;
import org.junit.Test;

public class GetDataTest extends JcardsimTestCase {
	@Test public void defaultName() {
		assertResponseData("" , "00CA005B00");
	}

	@Test public void defaultSex() {
		assertResponseData("30" , "00CA5F3500");
	}

	@Test public void defaultLanguage() {
		assertResponseData("656E" , "00CA5F2D00");
	}

	@Test public void defaultUserPUKTries() {
		assertResponseData("01404040030003", "00CA00C400");
	}

	//@Test public void defaultApplicationRelatedData() {
	//	assertResponseData(
	//		"6E647362C00A00000000000000000000C106010800001103C206010800001103" +
	//		"C306010800001103C53C00000000000000000000000000000000000000000000" +
	//		"0000000000000000000000000000000000000000000000000000000000000000" +
	//		"000000000000", "00CA006E00");
	//}

	@Test public void defaultURL() {
		assertResponseData("", "00CA5F5000FFFE");
	}
}
