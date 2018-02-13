##! Detect "bursting connections".

@load base/protocols/conn

module ConnBurst;

export {
	## The speed of a connection that is defined as "too fast" and
	## leads to the :bro:see:`ConnBurst::detected` event being
	## generated.  Defined in Mbps (Megabits per second).
	const speed_threshold: double = 50.0 &redef;

	## The threshold of data that must be transferred before connection
	## polling to measure speed is started.  Defined in MB (megabytes).
	const size_threshold: count = 100 &redef;

	## An event to indicate that a big and fast connection (bursty 
	## connection) was detected.
	global detected: event(c: connection, rate_in_mbps: double);
}

# Duration between polls of conn size after the ConnSize analyzer 
# has triggered.  You probably don't need to configure this.
const poll_interval = 500msecs &redef;

# This indicates how many times the speed will be checked after the size
# limit is hit.  You probably don't need to configure this.
const number_of_speed_polls = 5 &redef;

redef record connection += {
	clburst_last_Mb: count &default=0;
	clburst_last_ts: time &optional;
	clburst_hit: bool &default=F;
};

function speed_during_last_poll(c: connection): double
	{
	if ( ! c?$clburst_last_ts )
		c$clburst_last_ts = c$start_time;

	local Mb = (((c$orig$size + c$resp$size) * 8) / 1024 / 1024);
	local Mb_delta = Mb - c$clburst_last_Mb;

	local ts = network_time();
	local time_delta = interval_to_double(ts - c$clburst_last_ts);

	local Mbps = 0.0;
	if ( time_delta > 0 )
		Mbps = Mb_delta / time_delta;

	c$clburst_last_Mb = Mb;
	c$clburst_last_ts = ts;
	return Mbps;
	}

function size_callback(c: connection, cnt: count): interval
	{
	if ( c$clburst_hit )
		return -1sec;

	if ( cnt < number_of_speed_polls )
		{
		local speed = speed_during_last_poll(c);
		if ( speed > speed_threshold )
			{
			event ConnBurst::detected(c, speed);
			c$clburst_hit = T;

			# stop polling after this was detected.
			return -1sec;
			}

		return poll_interval;
		}
	else
		{
		local size_threshold_in_bytes = size_threshold * 1024 * 1024;

		# Set conn thresholds for the next jump up.
		local next_orig_multiplier = double_to_count(floor(c$orig$size / size_threshold_in_bytes));
		if ( next_orig_multiplier > 0 )
			ConnThreshold::set_bytes_threshold(c, (next_orig_multiplier+1) * size_threshold_in_bytes, T);
		
		local next_resp_multiplier = double_to_count(floor(c$resp$size / size_threshold_in_bytes));
		if ( next_resp_multiplier > 0 )
			ConnThreshold::set_bytes_threshold(c, (next_resp_multiplier+1) * size_threshold_in_bytes, F);

		# end this polling
		return -1sec;
		}
	}

event new_connection(c: connection)
	{
	# This deals with the fact that icmp connections can't be looked up and maybe 
	# some other situations too?
	if ( connection_exists(c$id) )
		{
		ConnThreshold::set_bytes_threshold(c, size_threshold * 1024 * 1024, T);
		ConnThreshold::set_bytes_threshold(c, size_threshold * 1024 * 1024, F);
		}
	}

event conn_bytes_threshold_crossed(c: connection, threshold: count, is_orig: bool)
	{
	# Make sure this is one of our callbacks
	if ( threshold % size_threshold == 0 )
		{
		ConnPolling::watch(c, size_callback, 0, poll_interval);
		}
	}

