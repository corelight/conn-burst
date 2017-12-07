@load ./main

module ConnBurst;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## Timestamp of when the burst was identified.
		ts          : time            &log;
		## Connection unique ID.
		uid         : string          &log;
		## Connection ID.
		id          : conn_id         &log;
		## Protocol of the connection.
		proto       : transport_proto &log;
		## Amount of data sent by the originator of the connection.
		orig_size   : count           &log;
		## Amount of data sent by the responder of the connection.
		resp_size   : count           &log;
		## Speed of the connection when the burst identification occurred.
		mbps        : double          &log;
		## How fast the connection was when the burst identication occurred.
		age_of_conn : interval        &log;
	};
}

redef record connection += {
	conn_burst: ConnBurst::Info &optional;
};

event bro_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=ConnBurst::Info, $path="conn_burst"]);
	}

event ConnBurst::detected(c: connection, rate_in_mbps: double) &priority=5
	{
	c$conn_burst = Info($ts=network_time(),
	                    $uid=c$uid,
	                    $id=c$id,
	                    $proto=get_port_transport_proto(c$id$resp_p),
	                    $orig_size=c$orig$size,
	                    $resp_size=c$resp$size,
	                    $mbps=rate_in_mbps,
	                    $age_of_conn=network_time()-c$start_time);
	}

event ConnBurst::detected(c: connection, rate_in_mbps: double) &priority=-5
	{
	Log::write(LOG, c$conn_burst);
	}
