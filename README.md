Connection Burst Identification
-------------------------------

This package identifies "bursting connections" which are considered to be 
connections which transfer a large amount of data quickly.  Once a bursty 
connection is identified it is no longer watched for being bursty.

When a bursty connection is identified, the event `ConnBurst::detected` is 
generated and a log is written to a log stream named `conn_burst`.

Installation
------------

	bro-pkg refresh
	bro-pkg install bro/corelight/conn-burst


Configuration
-------------

There are a couple of configuration options that might have an impact on
analysis and detection.

`ConnBurst::speed_threshold` - This is a `double` value defined in Mbps and 
it means that you consider a bursty connection on your network to be one 
that is transferring data faster than this rate. The default speed threshold
is `50Mbps`.

`ConnBurst::size_threshold` - This is a `double` value defined in MB and it 
means that you'd like a minimum of this much traffic transferred before the 
transfer rate of the connection is tested.  This avoids identifying a small
connection that happens to tranfer data quickly as bursty since it's likely 
that a small and fast connection doesn't really matter that much to your 
analysis. The default size threshold is `100MB`.

Usage
-----

When a connection burst is detected, it will generate the following event.
You can copy and paste this into your script if you want to do something
based on a connection bursting.

```bro
event ConnBurst::detected(c: connection, rate_in_mbps: double)
	{
	# Do something here!
	}
```

Acknowledgements
----------------

Thanks to Robin Sommer for the initial discussion on how to approach this 
problem efficiently.  Also, thanks to Aashish Sharma and Keith Lehigh for
prerelease testing and fixing a few bugs!

Authors
-------

 - Seth Hall <seth@corelight.com>
