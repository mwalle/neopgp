## Simulate a virtual NeoPGP smartcard

    # build
    $ ant
    # start the simulator
    $ java -cp lib/jcardsim-3.0.5-SNAPSHOT.jar:`pwd`/build/classes com.licel.jcardsim.remote.VSmartCard sim/jcardsim.cfg
    # create applet
    $ opensc-tool -s "80 b8 00 00 12 10 d2 76 00 01 24 01 03 04 ff ff 00 00 00 00 00 00 00 7f"
    # test selecting applet
    $ opensc-tool -s "00 a4 04 00 06 d2 76 00 01 24 01 00"
    # start gpg
    $ gpg --card-edit
