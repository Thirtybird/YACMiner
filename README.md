# YACMiner

YACMiner is a modified version of cgminer. Normal scrypt mining has been
replaced by scrypt-chacha mining which is compatible with Yacoin.

Original yacminer was created by hanzac
OpenCL kernel improvements and other fixes by mikaelh
Updates and implementation of new features by thirtybird

## About
This is a multi-threaded multi-pool GPU, FPGA and ASIC miner with ATI GPU
monitoring, (over)clocking and fanspeed support for yacoin and derivative
coins.

Releases: https://github.com/Thirtybird/YACMiner/releases

Source: https://github.com/Thirtybird/YACMiner

License: GPLv3.  See COPYING for details.

SEE ALSO API-README, ASIC-README, FGPA-README, GPU-README AND SCRYPT-README FOR
MORE INFORMATION ON EACH.

## Usage Summary

After saving configuration from the menu, you do not need to give yacminer any
arguments and it will load your configuration.

Any configuration file may also contain a single

	"include" : "filename"

to recursively include another configuration file.
Writing the configuration will save all settings from all files in the output.

#### Single pool

	yacminer -o http://pool:port -u username -p password

#### Multiple pools

	yacminer -o http://pool1:port -u pool1username -p pool1password -o http://pool2:port -u pool2usernmae -p pool2password

#### Single pool with a standard http proxy, regular desktop:

	yacminer -o "http:proxy:port|http://pool:port" -u username -p password

#### Single pool with a socks5 proxy, regular desktop

	yacminer -o "socks5:proxy:port|http://pool:port" -u username -p password

#### Single pool with stratum protocol support

	yacminer -o stratum+tcp://pool:port -u username -p password

### Proxy Yypes

	http:    standard http 1.1 proxy
	http0:   http 1.0 proxy
	socks4:  socks4 proxy
	socks5:  socks5 proxy
	socks4a: socks4a proxy
	socks5h: socks5 proxy using a hostname

If you compile yacminer with a version of CURL before 7.19.4 then some of the above will
not be available. All are available since CURL version 7.19.4

If you specify the --socks-proxy option to YACMiner, it will only be applied to all pools
that don't specify their own proxy setting like above

## Building YACMiner

### Dependencies
	curl dev library 	http://curl.haxx.se/libcurl/
	(libcurl4-openssl-dev)

	curses dev library
	(libncurses5-dev or libpdcurses on WIN32)

	pkg-config		http://www.freedesktop.org/wiki/Software/pkg-config
	libtool			http://www.gnu.org/software/libtool/

	AMD APP SDK		http://developer.amd.com/sdks/AMDAPPSDK
	(This sdk is mandatory for AMD GPU mining)

	jansson			http://www.digip.org/jansson/
	(jansson is included in-tree and not necessary)

	AMD ADL SDK		http://developer.amd.com/sdks/ADLSDK
	(This sdk is optional, and enabled AMD GPU monitoring & clocking)

	autoconf
	automake

### YACMiner specific configuration options
	--disable-adl           Override detection and disable building with adl
	--without-curses        Compile support for curses TUI (default enabled)

## Basic *nix build instructions
To actually build:

	./autogen.sh
	CFLAGS="-O2 -Wall -march=native" ./configure <options>

No installation is necessary. You may run YACMiner from the build directory directly.

## Windows build instructions
see windows-build.txt

# Usage instructions  
Run "yacminer --help" to see options:

Usage: . [-atDdGCgIKklmpPQqrRsTouvwOchnV] 
Options for both config file and command line:

	--api-allow         Allow API access (if enabled) only to the given list of [W:]IP[/Prefix] address[/subnets]
			    This overrides --api-network and you must specify 127.0.0.1 if it is required
			    W: in front of the IP address gives that address privileged access to all api commands
	--api-description   Description placed in the API status header (default: yacminer version)
	--api-groups        API one letter groups G:cmd:cmd[,P:cmd:*...]
			    See API-README for usage
	--api-listen        Listen for API requests (default: disabled)
			    By default any command that does not just display data returns access denied
			    See --api-allow to overcome this
	--api-network       Allow API (if enabled) to listen on/for any address (default: only 127.0.0.1)
	--api-port          Port number of miner API (default: 4028)
	--auto-fan          Automatically adjust all GPU fan speeds to maintain a target temperature
	--auto-gpu          Automatically adjust all GPU engine clock speeds to maintain a target temperature
	--balance           Change multipool strategy from failover to even share balance
	--benchmark         Run yacminer in benchmark mode - produces no shares (currently broken)
	--compact           Use compact display without per device statistics
	--debug|-D          Enable debug output
	--device|-d <arg>   Select device to use, one value, range and/or comma separated (e.g. 0-2,4) default: all
	--disable-rejecting Automatically disable pools that continually reject shares
	--expiry|-E <arg>   Upper bound on how many seconds after getting work we consider a share from it stale (default: 120)
	--failover-only     Don't leak work to backup pools when primary pool is lagging
	--fix-protocol      Do not redirect to a different getwork protocol (eg. stratum)
	--hotplug <arg>     Set hotplug check time to <arg> seconds (0=never default: 5) - only with libusb
	--kernel-path|-K <arg> Specify a path to where bitstream and kernel files are (default: "/usr/local/bin")
	--load-balance      Change multipool strategy from failover to efficiency based balance
	--log|-l <arg>      Interval in seconds between log output (default: 5)
	--lowmem            Minimise caching of shares for low memory applications
	--monitor|-m <arg>  Use custom pipe cmd for output messages
	--net-delay         Impose small delays in networking to not overload slow routers
	--nfmin <arg>       Set min N factor for mining scrypt-chacha coins (4 to 40)
	--nfmax <arg>       Set max N factor for mining scrypt-chacha coins (4 to 40)
	--no-submit-stale   Don't submit shares if they are detected as stale
	--nscrypt           Use the adaptive N-Factor scrypt algorithm for mining
	--pass|-p <arg>     Password for bitcoin JSON-RPC server
	--per-device-stats  Force verbose mode and output per-device statistics
	--protocol-dump|-P  Verbose dump of protocol-level activities
	--queue|-Q <arg>    Minimum number of work items to have queued (0 - 10) (default: 1)
	--quiet|-q          Disable logging output, display status and errors
	--real-quiet        Disable all output
	--remove-disabled   Remove disabled devices entirely, as if they didn't exist
	--rotate <arg>      Change multipool strategy from failover to regularly rotate at N minutes (default: 0)
	--round-robin       Change multipool strategy from failover to round robin on failure
	--scan-time|-s <arg> Upper bound on time spent scanning current work, in seconds (default: 60)
	--sched-start <arg> Set a time of day in HH:MM to start mining (a once off without a stop time)
	--sched-stop <arg>  Set a time of day in HH:MM to stop mining (will quit without a start time)
	--scrypt            Use the scrypt algorithm for mining
	--scrypt-chacha     Use the scrypt-chacha algorithm for mining (aka scrypt-jane)
	--sharelog <arg>    Append share log to file
	--shares <arg>      Quit after mining N shares (default: unlimited)
	--socks-proxy <arg> Set socks4 proxy (host:port) for all pools without a proxy specified
	--syslog            Use system log for output messages (default: standard error)
	--temp-cutoff <arg> Temperature where a device will be automatically disabled, one value or comma separated list (default: 95)
	--text-only|-T      Disable ncurses formatted screen output
	--url|-o <arg>      URL for bitcoin JSON-RPC server
	--user|-u <arg>     Username for bitcoin JSON-RPC server
	--verbose           Log verbose output to stderr as well as status output
	--userpass|-O <arg> Username:Password pair for bitcoin JSON-RPC server
	Options for command line only:
	--config|-c <arg>   Load a JSON-format configuration file
	See example.conf for an example configuration.
	--help|-h           Print this message
	--version|-V        Display version and exit

### GPU specific options

	--auto-fan          Automatically adjust all GPU fan speeds to maintain a target temperature
	--auto-gpu          Automatically adjust all GPU engine clock speeds to maintain a target temperature
	--buffer-size|-B <arg> Set OpenCL Buffer size in MB for scrypt mining, comma separated
	--disable-gpu|-G    Disable GPU mining even if suitable devices exist
	--gpu-dyninterval <arg> Set the refresh interval in ms for GPUs using dynamic intensity (default: 7)
	--gpu-engine <arg>  GPU engine (over)clock range in Mhz - one value, range and/or comma separated list (e.g. 850-900,900,750-850)
	--gpu-fan <arg>     GPU fan percentage range - one value, range and/or comma separated list (e.g. 25-85,85,65)
	--gpu-map <arg>     Map OpenCL to ADL device order manually, paired CSV (e.g. 1:0,2:1 maps OpenCL 1 to ADL 0, 2 to 1)
	--gpu-memclock <arg> Set the GPU memory (over)clock in Mhz - one value for all or separate by commas for per card.
	--gpu-memdiff <arg> Set a fixed difference in clock speed between the GPU and memory in auto-gpu mode
	--gpu-powertune <arg> Set the GPU powertune percentage - one value for all or separate by commas for per card.
	--gpu-reorder       Attempt to reorder GPU devices according to PCI Bus ID
	--gpu-threads|-g <arg> Number of threads per GPU - one value or comma separated list (e.g. 1,2,1)
	--gpu-vddc <arg>    Set the GPU voltage in Volts - one value for all or separate by commas for per card.
	--intensity|-I <arg> Intensity of GPU scanning (d or -10 -> 20, default: d to maintain desktop interactivity)
	--lookup-gap <arg>  Set GPU lookup gap, comma separated
	--kernel|-k <arg>   Override kernel to use (diablo, poclbm, phatk or diakgcn) - one value or comma separated
	--ndevs|-n          Enumerate number of detected GPUs and exit
	--no-restart        Do not attempt to restart GPUs that hang
	--rawintensity|-R <arg> Raw intensity of GPU scanning (1 - 2147483647), overrides --intensity|-I and --xintensity|-X
	--shaders <arg>     GPU shaders per card for tuning, comma separated
	--temp-hysteresis <arg> Set how much the temperature can fluctuate outside limits when automanaging speeds (default: 3)
	--temp-overheat <arg> Overheat temperature when automatically managing fan and GPU speeds (default: 85)
	--temp-target <arg> Target temperature when automatically managing fan and GPU speeds (default: 75)
	--thread-concurrency <arg> Set GPU thread concurrency, comma separated.  Overrides --shaders
	--vectors|-v <arg>  Override detected optimal vector (1, 2 or 4) - one value or comma separated list
	--worksize|-w <arg> Override detected optimal worksize - one value or comma separated list
	--xintensity|-X <arg> Shader based intensity of GPU scanning (1 - 9999), overrides --intensity|-I

See GPU-README for more information regarding GPU mining.

See SCRYPT-README for more information regarding Scrypt-Chacha mining.

## While Running

The following options are available while running with a single keypress:

### [P]ool management [G]PU management [S]ettings [D]isplay options [Q]uit

#### [P]ool management

	Current pool management strategy: Failover
	[F]ailover only disabled
	[A]dd pool [R]emove pool [D]isable pool [E]nable pool
	[C]hange management strategy [S]witch pool [I]nformation

#### [S]ettings

	[Q]ueue: 1
	[S]cantime: 60
	[E]xpiry: 120
	[W]rite config file
	[C]gminer restart

#### [D]isplay options

	[N]ormal [C]lear [S]ilent mode (disable all output)
	[D]ebug:off
	[P]er-device:off
	[Q]uiet:off
	[V]erbose:off
	[R]PC debug:off
	[W]orkTime details:off
	co[M]pact: off
	[L]og interval:5

#### [Q]uit

	Quits the application.


#### [G]PU management
gives you something like: (may be out of date or not relevent to YACoin)

	GPU 0: [124.2 / 191.3 Mh/s] [A:77  R:33  HW:0  U:1.73/m  WU 1.73/m]
	Temp: 67.0 C
	Fan Speed: 35% (2500 RPM)
	Engine Clock: 960 MHz
	Memory Clock: 480 Mhz
	Vddc: 1.200 V
	Activity: 93%
	Powertune: 0%
	Last initialised: [2011-09-06 12:03:56]
	Thread 0: 62.4 Mh/s Enabled ALIVE
	Thread 1: 60.2 Mh/s Enabled ALIVE

	[E]nable [D]isable [R]estart GPU [C]hange settings
	Or press any other key to continue

The running log shows output like this:

	[2012-10-12 18:02:20] Accepted f0c05469 Diff 1/1 GPU 0 pool 1
	[2012-10-12 18:02:22] Accepted 218ac982 Diff 7/1 GPU 1 pool 1
	[2012-10-12 18:02:23] Accepted d8300795 Diff 1/1 GPU 3 pool 1
	[2012-10-12 18:02:24] Accepted 122c1ff1 Diff 14/1 GPU 1 pool 1

The 8 byte hex value are the 2nd 8 bytes of the share being submitted to the
pool. The 2 diff values are the actual difficulty target that share reached
followed by the difficulty target the pool is currently asking for.

### Display values
#### Summary
At the top of the screen (with curses enabled) is the following summary

	(5s):8.462K (avg):8.365Kh/s | A:8894  R:10  HW:0  U:7.7/m  WU:7.7/m  FB:11

The columns are defined in the following way:

	5s:  A 5 second exponentially decaying average hash rate
	avg: An all time average hash rate
	A:   The number of Accepted shares
	R:   The number of Rejected shares
	HW:  The number of HardWare errors
	U:   The Utility defined as the number of shares / minute
	WU:  The Work Utility defined as the number of diff1 shares work / minute
	     (accepted or rejected).
	FB:  The number of blocks that have been found

Below that is the status line

	ST: 1  SS: 0  NB: 1  LW: 8  GF: 1  RF: 1  WU:4.4/m

The columns are defined in the following way:

	ST is STaged work items (ready to use).
	SS is Stale Shares discarded (detected and not submitted so don't count as rejects)
	NB is New Blocks detected on the network
	LW is Locally generated Work items
	GF is Getwork Fail Occasions (server slow to provide work)
	RF is Remote Fail occasions (server slow to accept work)
	WU is Work Utility (Rate of difficulty 1 shares solved per minute)

The block display shows:
Block: 0074c5e482e34a506d2a051a...  Started: [17:17:22]  Best share: 2.71K

This shows a short stretch of the current block, when the new block started,
and the all time best difficulty share you've found since starting yacminer
this time.

#### GPU status
Below the summary, each GPU is shown with its corresponding stats

	GPU 0:  42.0C 1061RPM | 2.090K/2.091Kh/s | A:2457 R: 0 HW:0 U:2.14/m T:1 rI: 808
	GPU 1:  44.0C 1042RPM | 2.090K/2.091Kh/s | A:2268 R: 0 HW:0 U:1.97/m T:1 rI: 808

The columns are defined in the following way:

	Temperature (if supported)
	Fanspeed (if supported)
	A 5 second exponentially decaying average hash rate
	An all time average hash rate
	A:   The number of Accepted shares
	R:   The number of rejected shares
	HW:  The number of hardware erorrs
	U:   The utility defined as the number of shares / minute
	T:   The number of cpu threads running on this GPU (defined by -g)
	I:   The Intensity setting of the GPU - lauches 2^Intensity GPU threads
	xI:  The Experimental Intensity setting - launches xI multiple of shader count threads
	rI:  The Raw Intensity setting - launches rI GPU threads

## Multipool

### Failover Strategies With Multipool
A number of different strategies for dealing with multipool setups are
available. Each has their advantages and disadvantages so multiple strategies
are available by user choice, as per the following list:

### Failover
The default strategy is failover. This means that if you input a number of
pools, it will try to use them as a priority list, moving away from the 1st
to the 2nd, 2nd to 3rd and so on. If any of the earlier pools recover, it will
move back to the higher priority ones.

### Round Robin
This strategy only moves from one pool to the next when the current one falls
idle and makes no attempt to move otherwise.

### Rotate
This strategy moves at user-defined intervals from one active pool to the next,
skipping pools that are idle.

### Load Balance
This strategy sends work to all the pools to maintain optimum load. The most
efficient pools will tend to get a lot more shares. If any pool falls idle, the
rest will tend to take up the slack keeping the miner busy.

### Balance
This strategy monitors the amount of difficulty 1 shares solved for each pool
and uses it to try to end up doing the same amount of work for all pools.

## Logging

YACMiner will log to stderr if it detects stderr is being redirected to a file.
To enable logging simply add 2>logfile.txt to your command line and logfile.txt
will contain the logged output at the log level you specify (normal, verbose,
debug etc.)

In other words if you would normally use:

	./yacminer -o xxx -u yyy -p zzz

if you use

	./yacminer -o xxx -u yyy -p zzz 2>logfile.txt

it will log to a file called logfile.txt and otherwise work the same.

There is also the -m option on linux which will spawn a command of your choice
and pipe the output directly to that command.

The WorkTime details 'debug' option adds details on the end of each line
displayed for Accepted or Rejected work done. An example would be:

	<-00000059.ed4834a3 M:X D:1.0 G:17:02:38:0.405 C:1.855 (2.995) W:3.440 (0.000) S:0.461 R:17:02:47

The first 2 hex codes are the previous block hash, the rest are reported in
seconds unless stated otherwise:
The previous hash is followed by the getwork mode used M:X where X is one of
P:Pool, T:Test Pool, L:LP or B:Benchmark,
then D:d.ddd is the difficulty required to get a share from the work,
then G:hh:mm:ss:n.nnn, which is when the getwork or LP was sent to the pool and
the n.nnn is how long it took to reply,
followed by 'O' on it's own if it is an original getwork, or 'C:n.nnn' if it was
a clone with n.nnn stating how long after the work was recieved that it was cloned,
(m.mmm) is how long from when the original work was received until work started,
W:n.nnn is how long the work took to process until it was ready to submit,
(m.mmm) is how long from ready to submit to actually doing the submit, this is
usually 0.000 unless there was a problem with submitting the work,
S:n.nnn is how long it took to submit the completed work and await the reply,
R:hh:mm:ss is the actual time the work submit reply was received

If you start YACMiner with the --sharelog option, you can get detailed
information for each share found. The argument to the option may be "-" for
standard output (not advisable with the ncurses UI), any valid positive number
for that file descriptor, or a filename.

To log share data to a file named "share.log", you can use either:

	./yacminer --sharelog 50 -o xxx -u yyy -p zzz 50>share.log
	./yacminer --sharelog share.log -o xxx -u yyy -p zzz

For every share found, data will be logged in a CSV (Comma Separated Value) format:

	timestamp,disposition,target,pool,dev,thr,sharehash,sharedata

For example (this is wrapped, but it's all on one line for real):

	1335313090,reject,
	ffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000,
	http://localhost:8337,GPU0,0,
	6f983c918f3299b58febf95ec4d0c7094ed634bc13754553ec34fc3800000000,
	00000001a0980aff4ce4a96d53f4b89a2d5f0e765c978640fe24372a000001c5
	000000004a4366808f81d44f26df3d69d7dc4b3473385930462d9ab707b50498
	f681634a4f1f63d01a0cd43fb338000000000080000000000000000000000000
	0000000000000000000000000000000000000000000000000000000080020000


## RPC API
For RPC API details see the API-README file

## FAQ

	Q: Can I mine on servers from different networks (eg yacoin and ybcoin) at
	the same time?
	A: No, yacminer keeps a database of the block it's working on to ensure it does
	not work on stale blocks, and having different blocks from two networks would
	make it invalidate the work from each other.  You can have a failover pool that
	mines a different coin though if you desire.

	Q: Can I configure YACMiner to mine with different login credentials or pools
	for each separate device?
	A: Yes, but only by launching multiple instances of YACMiner, specifying
	different devices for each instance.

	Q: Can I put multiple pools in the config file?
	A: Yes, check the example.conf file. Alternatively, set up everything either on
	the command line or via the menu after startup and choose settings->write
	config file and the file will be loaded one each startup.

	Q: The build fails with gcc is unable to build a binary.
	A: Remove the "-march=native" component of your CFLAGS as your version of gcc
	does not support it.

	Q: Can you implement feature X?
	A: I can, but time is limited, and people who donate are more likely to get
	their feature requests implemented.

	Q: Work keeps going to my backup pool even though my primary pool hasn't
	failed?
	A: YACMiner checks for conditions where the primary pool is lagging and will
	pass some work to the backup servers under those conditions. The reason for
	doing this is to try its absolute best to keep the GPUs working on something
	useful and not risk idle periods. You can disable this behaviour with the
	option --failover-only.

	Q: Is this a virus?
	A: YACMiner is being packaged with other trojan scripts and some antivirus
	software is falsely accusing yacminer.exe as being the actual virus, rather
	than whatever it is being packaged with. If you installed YACMiner yourself,
	then you do not have a virus on your computer. Complain to your antivirus
	software company. They seem to be flagging even source code now from cgminer
	and its derivitives as viruses, even though text source files can't do 
	anything by themself.

	Q: Can you modify the display to include more of one thing in the output and
	less of another, or can you change the quiet mode or can you add yet another
	output mode?
	A: Everyone will always have their own view of what's important to monitor.
	The defaults are very sane and I have very little interest in changing this
	any further.

	Q: What are the best parameters to pass for X pool/hardware/device.
	A: Virtually always, the DEFAULT parameters give the best results. Most user
	defined settings lead to worse performance. The ONLY thing most users should
	need to set is the Intensity for GPUs.

	Q: What happened to CPU mining?
	A: CPU mining was never available in YACMiner, however, there is a CPU Miner
	for mining YACoin available at http://github.com/Thirtybird/cpuminer.

	Q: GUI version?
	A: No. The RPC interface makes it possible for someone else to write one
	though.

	Q: I'm having an issue. What debugging information should I provide?
	A: Start yacminer with your regular commands and add -D -T --verbose and provide
	the full startup output and a summary of your hardware, operating system, AMD
	driver version and AMD stream version.

	Q: Why don't you provide win64 builds?
	A: Win32 builds work everywhere and there is precisely zero advantage to a
	64 bit build on Windows.

	Q: Is it faster to mine on windows or linux?
	A: It makes no difference. It comes down to choice of operating system for
	their various features. Linux offers much better long term stability and
	remote monitoring and security, while windows offers you overclocking tools
	that can achieve much more than YACMiner can do on linux.

	Q: Can I mine with yacminer on a MAC?
	A: (unknown - previous answer for cgminer is as follows)
	cgminer will compile on OSX, but the performance of GPU mining is
	compromised due to the opencl implementation on OSX, there is no temperature
	or fanspeed monitoring, and the cooling design of most MACs, despite having
	powerful GPUs, will usually not cope with constant usage leading to a high
	risk of thermal damage. It is highly recommended not to mine on a MAC unless
	it is to a USB device.

	Q: I switch users on windows and my mining stops working?
	A: That's correct, it does. It's a permissions issue that there is no known
	fix for due to monitoring of GPU fanspeeds and temperatures. If you disable
	the monitoring with --no-adl it should switch okay.

	Q: My network gets slower and slower and then dies for a minute?
	A; Try the --net-delay option.

	Q: How do I tune for p2pool?
	A: p2pool has very rapid expiration of work and new blocks, it is suggested you
	decrease intensity by 1 from your optimal value, and decrease GPU threads to 1
	with -g 1. It is also recommended to use --failover-only since the work is
	effectively like a different block chain. If mining with a minirig, it is worth
	adding the --bfl-range option.

	Q: I run PHP on windows to access the API with the example miner.php. Why does
	it fail when php is installed properly but I only get errors about Sockets not
	working in the logs?
	A: http://us.php.net/manual/en/sockets.installation.php

	Q: What is stratum and how do I use it?
	A: Stratum is a protocol designed for pooled mining in such a way as to
	minimise the amount of network communications, yet scale to hardware of any
	speed. If a pool has stratum support, YACMiner will automatically detect it and 
	switch to the support as advertised if it can.
	Stratum uses direct TCP connections to the pool and thus it will NOT currently
	work through a http proxy but will work via a socks proxy if you need to use
	one. If you input the stratum port directly into your configuration, or use the
	special prefix "stratum+tcp://" instead of "http://", YACMiner will ONLY try to
	use stratum protocol mining. The advantages of stratum to the miner are no
	delays in getting more work for the miner, less rejects across block changes,
	and far less network communications for the same amount of mining hashrate. If
	you do NOT wish YACMiner to automatically switch to stratum protocol even if it
	is detected, add the --fix-protocol option.

	Q: Why does the difficulty not match with the current difficulty target?
	A: The current scrypt block difficulty is expressed in terms of how many
	multiples of the BTC difficulty it currently is (eg 28) whereas the shares of
	"difficulty 1" are actually 65536 times smaller than the BTC ones. The diff
	expressed by YACMiner is as multiples of difficulty 1 shares.

	Q: Can I use a proxy?
	A: Proxies only work with the getwork and GBT protocols using the --proxy
	command. If you wish to use a proxy with stratum, people have supported
	success with various 3rd party tools like proxifier.

## Disclaimer 

This code is provided entirely free of charge by the programmer in his spare
time so donations would be greatly appreciated. Please consider donating to the
address below.

Thirtybird
BTC: 183eSsaxG9y6m2ZhrDhHueoKnZWmbm6jfC
YAC: Y4FKiwKKYGQzcqn3M3u6mJoded6ri1UWHa
