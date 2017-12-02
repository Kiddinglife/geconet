
"""
since the CHALLENGE messages must include the correct COOKIE, it means that all 
flooding clients are using their real IP addresses.  So the server might automatically 
enter a new firewall rule to ignore packets from their IP address.

Why control chunks always before DATA chunks?
thisi s for effciency because we always need to detect some certain ctrl chunks
in an packet and the number of DATA chunks uaually is more than that of ctrl chunks

RFC 4960 


SECTION 3 SCTP Packet Format
1) 
INIT, INIT ACK, and SHUTDOWN COMPLETE chunks.
MUST NOT be bundled with any other chunk in a packet.
2)  
All integer fields in an SCTP packet MUST be transmitted in network
byte order, unless otherwise stated.
3) 
Source Port Number is the SCTP sender's port number. 
It can be used by the receiver in combination with the source IP address, 
the SCTP destination port, and possibly the destination IP address to
identify the association to which this packet belongs.
Source Port Number MUST NOT be 0
Dest Port Number MUST NOT be 0
4) 
A packet containing an INIT chunk MUST have a zero Verification Tag.
A packet containing a SHUTDOWN COMPLETE chunk with the T bit
set MUST have the Verification Tag copied from the packet with
the SHUTDOWN ACK chunk.
5)
A packet containing an ABORT chunk may have the verification
tag copied from the packet that caused the ABORT to be sent.


SECTION 3.2 Chunk Field Descriptions
6)
Chunk Types are encoded such that the highest-order 2 bits specify
the action that must be taken if the processing endpoint does not
recognize the Chunk Type.
7)
if the Chunk Value field is zero-length, the Length
field will be set to 4.  The Chunk Length field does not count any
chunk padding.
8)
However, it does include padding of any variable-length
parameter except the last parameter in the chunk.  The receiver
MUST ignore the padding.
9) 
A robust implementation should accept the chunk whether or
not the final padding has been included in the Chunk Length.


10)
Please note that in all four cases, an INIT ACK or COOKIE ECHO chunk
is sent.  In the 00 or 01 case, the processing of the parameters
after the unknown parameter is canceled, but no processing already
done is rolled back.

11)
refers to section 3.2.2 


3.3.1.  Payload Data (DATA) (0)
12)
A DATA chunk with a User Data field of length L will have the
Length field set to (16 + L) (indicating 16+L bytes) where L MUST
be greater than 0.
13)
the same Stream Sequence Number MUST be carried in each of the
fragments of the message.


3.3.2.  Initiation (INIT) (1)
14)
An INIT chunk MUST NOT contain more than one Host Name
Address parameter.  Moreover, the sender of the INIT MUST NOT combine
any other address types with the Host Name Address in the INIT.
15)
Combined with the Source Port Number in the SCTP common header,
the value passed in an IPv4 or IPv6 Address parameter indicates a
transport address the sender of the INIT will support for the
association being initiated.  That is, during the life time of
this association, this IP address can appear in the source address
field of an IP datagram sent from the sender of the INIT, and can
be used as a destination address of an IP datagram sent from the
receiver of the INIT.
16)
IMPLEMENTATION NOTE: If an INIT chunk is received with known
parameters that are not optional parameters of the INIT chunk, then
the receiver SHOULD process the INIT chunk and send back an INIT ACK.
The receiver of the INIT chunk MAY bundle an ERROR chunk with the
COOKIE ACK chunk later.  However, restrictive implementations MAY
send back an ABORT chunk in response to the INIT chunk.
17)
The receiver of the INIT (the responding end) records the value of
the Initiate Tag parameter.
18)
If the value of the Initiate Tag in a received INIT chunk is found
to be 0, the receiver MUST treat it as an error and close the
association by transmitting an ABORT.
19)
A receiver of an INIT with the OS value set to 0 SHOULD abort the association.
20)
Thevalue 0 MUST NOT be used for MIS
21)
Note: There is no negotiation of the actual number of streams but
instead the two endpoints will use the min(requested, offered).
See Section 5.1.1 for details.
22)
Note: A receiver of an INIT with the MIS value of 0 SHOULD abort
the association.
23)
Initial TSN (I-TSN) field MAY be set to the value of the Initiate Tag field.
24)


3.3.2.1.  Optional/Variable-Length Parameters in INIT
24)
Combined with the Source Port Number in the SCTP common header,
    the value passed in an IPv4 or IPv6 Address parameter indicates a
    transport address the sender of the INIT will support for the
    association being initiated. 
25)
If the INIT contains at least one IP Address parameter, then the
    source address of the IP datagram containing the INIT chunk and
    any additional address(es) provided within the INIT can be used as
    destinations by the endpoint receiving the INIT.  If the INIT does
    not contain any IP Address parameters, the endpoint receiving the
    INIT MUST use the source address associated with the received IP
    datagram as its sole destination address for the association.
      
      
3.3.3.  Initiation Acknowledgement (INIT ACK) (2)
26)
If the value of the Initiate Tag in a received INIT ACK chunk is
found to be 0, the receiver MUST destroy the association
discarding its TCB.  The receiver MAY send an ABORT for debugging
purpose.
27)
Note: A receiver of an INIT ACK with the MIS value set to 0 SHOULD
destroy the association discarding its TCB.
28)
Moreover, the sender of the INIT ACK MUST NOT
combine any other address types with the Host Name Address in the
INIT ACK.  The receiver of the INIT ACK MUST ignore any other address
types if the Host Name Address parameter is present.
29)
IMPLEMENTATION NOTE: An implementation MUST be prepared to receive an
INIT ACK that is quite large (more than 1500 bytes) due to the
variable size of the State Cookie AND the variable address list.  
30)
IMPLEMENTATION NOTE: If an INIT ACK chunk is received with known
parameters that are not optional parameters of the INIT ACK chunk,
then the receiver SHOULD process the INIT ACK chunk and send back a
COOKIE ECHO.  The receiver of the INIT ACK chunk MAY bundle an ERROR
chunk with the COOKIE ECHO chunk.  However, restrictive
implementations MAY send back an ABORT chunk in response to the INIT
ACK chunk.
31)
This parameter value MUST contain all the necessary state and
parameter information required for the sender of this INIT ACK to
create the association, along with a Message Authentication Code
(MAC).  See Section 5.1.3 for details on State Cookie definition.
32)


3.3.4.  Selective Acknowledgement (SACK) (3)
32)
This chunk is sent to the peer endpoint to acknowledge received DATA
chunks and to inform the peer endpoint of gaps in the received
subsequences of DATA chunks as represented by their TSNs.


3.3.6.  Heartbeat Acknowledgement (HEARTBEAT ACK) (5)
33)
An endpoint should send this chunk to its peer endpoint as a response
to a HEARTBEAT chunk (see Section 8.3).  A HEARTBEAT ACK is always
sent to the source IP address of the IP datagram containing the
HEARTBEAT chunk to which this ack is responding.

3.3.7.  Abort Association (ABORT) (6)
34)
DATA chunks MUST NOT be
bundled with ABORT.  Control chunks (except for INIT, INIT ACK, and
SHUTDOWN COMPLETE) MAY be bundled with an ABORT, but they MUST be
placed before the ABORT in the SCTP packet or they will be ignored by
the receiver.
35)
If an endpoint receives an ABORT with a format error or no TCB is
found, it MUST silently discard it.  Moreover, under any
circumstances, an endpoint that receives an ABORT MUST NOT respond to
that ABORT by sending an ABORT of its own. 

5.  Association Initialization  
35)
IMPLEMENTATION NOTE: An implementation may choose to send the
Communication Up notification to the SCTP user upon reception of a
valid COOKIE ECHO chunk.
36)
An endpoint MUST send the INIT ACK to the IP address from which it
received the INIT.
37)
If an endpoint receives an INIT, INIT ACK, or COOKIE ECHO chunk but
decides not to establish the new association due to missing mandatory
parameters in the received INIT or INIT ACK, invalid parameter
values, or lack of local resources, it SHOULD respond with an ABORT
chunk.  It SHOULD also specify the cause of abort, such as the type
of the missing mandatory parameters, etc., by including the error
cause parameters with the ABORT chunk.  The Verification Tag field in
the common header of the outbound SCTP packet containing the ABORT
chunk MUST be set to the Initiate Tag value of the peer.
38)
Note that a COOKIE ECHO chunk that does NOT pass the integrity check
is NOT considered an 'invalid parameter' and requires special
handling; see Section 5.1.5.
39)
IMPLEMENTATION NOTE: The IP addresses and SCTP port are generally
used as the key to find the TCB within an SCTP instance.
40)
REFERS TO 5.1.2.  Handle Address Parameters
41)
the receiver MUST derive and record all the
transport addresses from the received chunk AND the source IP
address that sent the INIT or INIT ACK. 
42)
After the association is initialized, the valid outbound stream
identifier range for either endpoint shall be 0 to min(local OS,
remote MIS)-1.

5.1.2.  Handle Address Parameters
43)
After all transport addresses are derived from the INIT or INIT ACK
chunk using the above rules, the endpoint shall select one of the
transport addresses as the initial primary path.
44)
The sender of INIT may include a 'Supported Address Types' parameter
in the INIT to indicate what types of address are acceptable.  When
this parameter is present, the receiver of INIT (initiate) MUST
either use one of the address types indicated in the Supported
Address Types parameter when responding to the INIT, or abort the
association with an "Unresolvable Address" error cause if it is
unwilling or incapable of using any of the address types indicated by
its peer.
45)
"""

"""
The general strategy is for the Packetization Layer to find an
appropriate Path MTU by probing the path with progressively larger
packets.  If a probe packet is successfully delivered, then the
effective Path MTU is raised to the probe size.
"""
probing_path_with_progressively_larger_packets()
if probe_acked:
	effective_path_mtu = probe_size


##################### HB ############################################
"""
    6.1.  Mechanism to Detect Loss

        It is important that the Packetization Layer has a timely and robust
        mechanism for detecting and reporting losses.  PLPMTUD makes MTU
        adjustments on the basis of detected losses.  Any delays or
        inaccuracy in loss notification is likely to result in incorrect MTU
        decisions or slow convergence. 
 
        It is important that the mechanism can robustly distinguish between 
        the isolated loss of just a probe and 
        other losses in the probe's leading and trailing windows.
        t0:leadwin --- t1:probsent --- t2:trailwin --- t3:probeacked 
        [ Leading window:  Any unacknowledged data in a flow at the time a probe is sent.
        Trailing window:  Any data in a flow sent after a probe, but before the probe is acknowledged. ]

        It is best if Packetization Protocols use an explicit loss detection
        mechanism such as a Selective Acknowledgment (SACK) scoreboard
        [RFC3517] or ACK Vector [RFC4340] to distinguish real losses from
        reordered data, although implicit mechanisms such as TCP Reno style
        duplicate acknowledgments counting are sufficient.

   7.1.  Packet Size Ranges

        describes the probing method using three state variables:
            search_low:          
                @note: search_low is fixed 
                The smallest useful probe size, minus one.  The network
                is expected to be able to deliver packets of size search_low.
            eff_pmtu:  
                The effective PMTU for this flow.  This is the largest 
                non-probe packet permitted by PLPMTUD for the path.
            search_high: 
                @note: search_high is un-fixed
                The greatest useful probe size.  Packets of size search_high are 
                expected to be too large for the network to deliver.

        When transmitting non-probes, the Packetization Layer SHOULD create 
        packets of a size less than or equal to eff_pmtu.

        When transmitting probes, the Packetization Layer MUST select a probe
        size that is larger than search_low and smaller than or equal to
        search_high.

        When probing upward, eff_pmtu always equals search_low.  Normally,
        eff_pmtu will be greater than or equal to search_low and less than
        search_high.  It is generally expected but not required that probe
        size will be greater than eff_pmtu.

        For initial conditions when there is no information about the path,
        eff_pmtu may be greater than search_low.  The initial value of
        search_low SHOULD be conservatively low, but performance may be
        better if eff_pmtu starts at a higher, less conservative, value.  See
        Section 7.2.
"""

"""
    7.2.  Selecting Initial Values

        The initial value for search_high SHOULD be the largest possible
        packet that might be supported by the flow.  the initial value for
        search_high MAY be limited by a configuration option to prevent
        probing above some maximum size.  
"""
search_high_init = 1500
search_high = search_high_init
search_high_ulp = 65535
search_high = search_high_ulp

"""  
        It is RECOMMENDED that search_low be initially set to an MTU size
        that is likely to work over a very wide range of environments.  Given
        today's technologies, a value of 1024 bytes is probably safe enough.
        The initial value for search_low SHOULD be configurable.
"""
search_low_default = 1024
search_low = search_low_default 
search_low_ulp = 1400
search_low = search_low_ulp 

"""
       Note that the initial eff_pmtu can be any value in the range
       search_low to search_high.  An initial eff_pmtu of 1400 bytes might
       be a good compromise because it would be safe for nearly all tunnels
       over all common networking gear, and yet close to the optimal MTU for
       the majority of paths in the Internet today
"""
initial_eff_pmtu = 1400


"""
        when on_communiction_up() called, 
        if peer ip is loopback ip or localhost ip or lan ip, 
        no need to probe and use 1500 as effpmtu
        All lan addr:
        > 192.168.0.0 - 192.168.255.255 (65,536 IP addresses)
        > 172.16.0.0 - 172.31.255.255 (1,048,576 IP addresses)
        > 169.254.0.0 - 169.254.255.255 (65,536 IP addresses)
        > 10.0.0.0 - 10.255.255.255 (16,777,216 IP addresses)
        @note: unaccepted as effpmtu is possible to be lower than 1500 in lan network
"""

"""
        Each Packetization Layer MUST determine when probing has converged,
        that is, when the probe size range is small enough that further
        probing is no longer worth its cost.  When probing has converged, a
        timer SHOULD be set.  When the timer expires, search_high should be
        reset to its initial value (described above) so that probing can
        resume.  Thus, if the path changes, increasing the Path MTU, then the
        flow will eventually take advantage of it.  The value for this timer
        MUST NOT be less than 5 minutes and is recommended to be 10 minutes,
        per RFC 1981.
        @note: search_low is fixed and change search high and effpmtu
"""


"""
        Whenever the MTU is raised, the congestion state variables MUST be
        rescaled so as not to raise the window size in bytes (or data rate in
        bytes per seconds).

        For many implementations, a flown would naturally correspond to an
        instance of each protocol (i.e., each connection or session). 

        server shoulld cache effpmtu for a peer.  If connect again shortly, it should still use that effpmtu. 
        If the MTU matches the outgoing interface,  there is no need for the system to cache that entry 
        taking up more resources on the server. 
"""

"""
    7.4.  Probing Preconditions

       Before sending a probe, the flow MUST meet at least the following
       conditions:

       o  It has no outstanding probes or losses.

       o  If the last probe failed or was inconclusive, then the probe
          timeout has expired (see Section 7.6.2).

       o  The available window is greater than the probe size.

       o  For a protocol using in-band data for probing, enough data is
          available to send the probe.

        The delayed sending
        algorithm SHOULD use some self-scaling technique to appropriately
        limit the time that the data is delayed.  
        >>>>>> we send d1, d2, hb, d3,d4, 5 chunks to peer continuesouly where d12 are leading window and d34 are trailing windows
        >>>>>>>>> we send some more dchuks
        >>>>>>>>>>>>> we recv sack,
        >>>>>>>>>>>>>>>>> hb timer timeouts,  if d1234 are all acked, hb must be the only loss
"""
# init mpath.probe_timer_timoeout = 1 second
# init each path.congested_during_fast_probe = True

#@note: 
# 1.
# dumy_packet_length is the length of packet that does not carry any data and
# it is only tens of bytes long and so must work in all nerworks.
# its values is sctphdrlen + iphdrlen.  The use of it is to ensure that even
# though all pmtus exclusive search_low exceed max-link-mtu without cogestions,
# mpath.fast_probe_timer can still quickly timeout and then notify ulp
# connection up with smallest pmtu applied.
# update rto rtt and headoff timeout when it is acked.  if not ackd，must be
# congested and then we need update comgestion stat.
# 3 dummy hb ensures that in the worst case where all other hb exceeds tu
# limit, we can headoff timout for around INIT_RTO/2/2/2
#
# 2. 
# when to probe all idle path after conn up,  use jump_probe_sizes = [probe_size, dumy_probe_length] 

jump_probe_sizes = [search_high, v1,  v2 , v3, v4,dumy_packet_length] 
def mrecv_on_conn_up():
    for probe_size in jump_probe_sizes:
        hbchunk = mchunk_make_hb(probe_size)
        msm_send_packet(hbchunk)

def on_hb_acked(effpmtu, path):
    if mpth.is_quick_probe:
        mpath_update_rtt_and_rto()
        if effpmtu > 0: # ignore dummy packet
            path.effpmtu = effpmtu
            path.congested_during_fast_probe = False
        mpath.quick_probe_counter+=1
        if mpath.quick_probe_counter < sizeof(jump_probe_sizes):
            # headoff timeout when there are hb acked
            mtran_reset_timout(timer = path.quick_probe_timer, newtimeout=mpath_quick_probe_expired.get_rto(rtt / mpath.quick_probe_counter))
        else:
            # all hbs are acked we can delete timer now 
             mtran_remove_timer(path.quick_probe_timer)
             # all hbs are acked we can call timeout imediately 
             mpath_quick_probe_expired()  
    else:
        # @TODO: send probes
        pass

def mpath_quick_probe_expired():
    for path  in mpath.paths:
        if path.congested_during_fast_probe:
            mrel_update_congestion_stats()
            mpath_backoff_rto()
    pid = find_path_with_highest_pmtu()
    mpath_set_primary_path(pid)
    mpth.is_quick_probe = False
    ulp_conn_up()





