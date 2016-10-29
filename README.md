![gecostacklogo](https://media.licdn.com/media/AAEAAQAAAAAAAALQAAAAJDI3NjViNjAxLTA5NDItNGJkMi05ZThlLThmM2VlODkyMmQwZA.png)

# Aimed for Online Games

**geconet** is a complete transport protocol stack on OSI layer 4(like TCP or Reliable-UDP).  
It is implemented in the user space with raw sockets and/or udp sockets(setup by users).  
It is specifically designed for datagram-like meassage trasport in online games.   
However, it is generic and may supersede TCP and Reliable-UDP in other applications as well.

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

- **againest denial of service,man-in-the-middle and blind attacks**   
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
