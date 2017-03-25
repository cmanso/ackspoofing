# ackspoofing
TCP Congestion Signaling via ACK Spoofing
This program was developed for my Bachelor's Thesis, which implemented a new TCP congestion notification mechanism in research by Zhong Xu and Mart Molle. It basically consists on spoofing 3 ACK packets to mimic the behaviour when TCP loses a packet. I used it inside a simulation of a satellite network, where the router in charge of uploading all the information to the satellite can inform the final clients the queue is full before it happens and the satellite start losing packets, causing a great damage to the link.

It worked fine on TCP Reno, but not so well on other TCP implementations.

I uploaded it here just as a sample of my coding skills, or lack of them :), so if anyone is interested in the program, just let me know and I can provide the simulation framework or any kind of information.
