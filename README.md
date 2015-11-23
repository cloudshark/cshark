# Cshark - CloudShark capture tool

Capture traffic and upload it directly to [CloudShark](https://www.cloudshark.org "CloudShark") for analysis.
Use the CloudShark service at https://www.cloudshark.org or your own CloudShark appliance.

## Building

##### Prerequisites (Linux):

* GCC 4.2+
* CMake 2.6+
* GNU Make 3.81+
* libubox
* uclient
* libuci
* libpcap
* json-c

##### Linux:
    cd build
    cmake ..
    make
    make install

## Configuration

Configuration is located in the ```/etc/config/cshark```.

## Usage

**Capture traffic on all interfaces and upload capture to** [CloudShark.org](https://www.cloudshark.org "CloudShark")

    cshark
or

    cshark -i any


**```NOTE```** To stop the capture press ```Ctrl```+```C``` after which upload will start. If you want
to stop upload, press ```Ctrl```+```C``` again.

**Capture traffic on specific interface and start upload after 5s timeout:**

    cshark -i eth0 -T 5

    capturing traffic to file: '/tmp/cshark.pcap-ht3Bqi' ...
    uploading capture ...
    ... uploading completed!
	https://openwrt.cloudshark.org/captures/379d474274d0

**Capture traffic until 50 packets are captured and write capture data to a file**

    cshark -i eth0 -P 50 -w capture.pcap

    capturing traffic to file: 'capture.pcap' ...
    uploading capture ...
    ... uploading completed!
	https://openwrt.cloudshark.org/captures/3bf8ee999968

**Capture traffic until 1000 bytes are captured, keep the dump file and apply filter:**

    cshark -i eth0 -k -S 1000 -s0 host 8.8.8.8

    capturing traffic to file: '/tmp/cshark.pcap-8OOjCv' ...
    uploading capture ...
    ... uploading completed!
	https://openwrt.cloudshark.org/captures/c43567e73137

**Filtering**

Everything after the last argument is taken and validated as a filter option.
For more info about available filter options see ```man pcap-filter```.


**All options**

To see all available options:

    cshark -h

    usage: cshark [-iwskTPSpvh] [ expression ]

    -i listen on interface
    -w write the raw packets to specific file
    -s snarf snaplen bytes of data
    -k keep the file after uploading it to cloudshark.org
    -T stop capture after this many seconds have passed, use 0 for no timeout
    -P stop capture after this many packets have been captured, use 0 for no limit
    -S stop capture after this many bytes have been saved, use 0 for no limit
    -p save pid to a file
    -v shows version
    -h shows this help
