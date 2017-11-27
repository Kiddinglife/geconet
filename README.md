![gecostacklogo](https://media.licdn.com/media/AAEAAQAAAAAAAALQAAAAJDI3NjViNjAxLTA5NDItNGJkMi05ZThlLThmM2VlODkyMmQwZA.png)


## Aimed for Online Games

GecoNet™ is an Open Source/Free Software cross-platform complete transport protocol stack 
similar to TCP and Reliable-UDP. It is implemented in the user space with raw sockets and/or udp sockets(setup by users).
However, it is generic and may supersede TCP and Reliable-UDP in other applications as well.
building upon RFC-4960 standards and currently supports Windows, Linux and Mac.  

GecoNet is not a simple rebranding of **RFC4960-SCTP-PROTOCOL**, but rather incorporates already
in its initial version several bug- and security fixes as well as new features to make it 
more suitable for games developments:
  - Packetization Layer Path MTU Discovery, 
  - Reliable-Sequenced, Reliable-unordered, Unreliable-Sequenced and Unreliable-Unordered
  - Load sharing between multi-connections from a single client host
  - Non-renegable selective ack
  - Build-in secured transmission
  - Better congestion control windows for overgrowth during changeover 
  - Quick Failover Algorithm

## Core Features
- **Secured connection pharse and encryption of messages**   
fast encrrption and compression of application messages.  
Secured connection based on key-exchange.  
key exchange methods (RAS & DH).  
encrption methods (DES_CBC, 3DES_CBC, ASE128,AES192).  
Hash methods (MD5, SHA-1).

- **(De)compression for game messages**  
since game packets often have small repeated blocks of data (IP packets, game messages hdr etc...),  
LZF3.6 (http://oldhome.schmorp.de/marc/liblzf.html) will be used in client-server model(config by users)  
as (de)compression method(formular:Time=1/Ratio+ActualBandwidth*(1/DecompressVelocity+1/CompressVelocity).    
Therefore, LZF3.6 is best option to achieve highest network throughput when bandwidth < 133 Mbps  
(the bandwidth most game clients have).

- **Multiple levels of message reliability**    
reliable and order, reliable and out-of-order, 
unreliable and order, unliable and out-of-order

- **Congestion avoidance**   
simlar but enhanced functionality as in TCP to avoid congestion with quicker slow-start-pharse

- **Multiple Transfer Channels**    
Support for more than one logical transfer channels of application messages.

- **Message-oriented**   
Preservation of apllication message boundaries.

- **Multihoming for network redundancy**  
use of multiple IP addresses per connection to allow transmission  
of data chunks through different network paths with highest pmtu

- **Fragmentation and PMTU**  
Detection of path MTU impelmented based on RFC 4821 - Packetization  
Layer Path MTU Discovery (https://www.ietf.org/rfc/rfc4821.txt).  
Fragmentation of user data to fit best into the highest pmtu

- **Error correction**  
Error-free, non-duplicated and non-corrupted data transfer


## Why use geconet instead of TCP or Reliable UDP？
- **no head-of-line blocking**      
TCP imposes a strictly reliable and ording data transmittions. However, if a user data message  
is lost during transit, all subsequent user data messages are delayed until the lost messag   
has been retransmitted (so-called head-of-line blocking). Some applications do not require a   
strict ordering of reliable messages. E.g. the complicated MMORPG or MOBA games usually exchange   
unrelated game messages out-of-order.  

- **no stream-oriented data transfer**   
TCP is stream-oriented. This means that TCP treats data chunks transmitted by an application as   
an ordered stream of bytes(=octets in network speak). While this concept supports a wide range of   
applications (mesage-oriented like email, character-oriented like TELNET, stream-oriented vides),   
it is unsuilted in most applications because these exchange application level messages with message  
boundaries. **geconet** preserves apllication level message boundaries, thus liberationg applications   
from implementing a framing protocol on the top of the transport protocol for delineating messages.   
**geconet** simply maps application messages to chunks on the transmit path and back to application   
messages on the receive path.  

- **multihoming**  
multihoming refers to the use of multiple IP addresses on either side of the connection to allow multiple  
transmission paths through the network thus increasing reliability and availability. TCP does not support   
multihoming since a TCP connection is defined by the quadruple source IP, destination IP, source port and  
destination port. **geconet** has built-in support for multihoming which offloads high-availability applications  
from implementing this feature.  

- **againest denial of service attacks**   
the connection setup of TCP allows denial of attacks, particularly SYN attacks. Each time the TCP layer    
receives a SYN packet for setting up a new connection, it allocates a data structure for storing connection    
parameters. Flodding with a high number of such SYN packets may lead to memory exhaustion. **geconet**  
implements a procedure to avoid or at least make it more diffcult for an attacker to lauch a connection denial    
of service attack (4-way connection setup with cookie).  

- **againest blind attacks**  
the connection setup of TCP allows blind attacks, particularly in applications that indentify users with their  
IP addreses. TCP receiver and sender initialize a SYN for setting up a new connection with use of tick-based  
random number generator. There is a high possibilty for an attacker to guess the right value of SYN so that he  
can proof an use  connecting and running commands in peer's machine. **geconet** carefully choose a time-unrelated  
verification number for each established connection in order to avoid or at least make it more diffcult for an  
attacker to lauch blind or proofing attacks.  

## Architecture

waiting...

## 
