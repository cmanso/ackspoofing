/**
 * @file	simpletun_advanced.c
 * @author	Carlos Manso
 * @brief	Tunnelling Program with ACK spoofing
 * @date	June 2016
 * @license GNU GPL	v3
 *
 * Based on simpletun.c from Davide Brini (C) 2009 
 * A simplistic, simple-minded, naive tunnelling program using tun/tap interfaces and TCP.
 * Handles IPv4 for tun, ARP and IPv4 for tap.                     
 * 
 * Now, includes a queue between tap and socket and another queue in the reverse path, with control of packet rate.
 *
 *                                 __________
 *                            ---->__________|O--->
 *                           |        Qtap         |
 *                  tap <--->|                     |<---> tcp socket
 *                  (fdtap)  |      __________     |       (fdsock)
 *                            <---O|__________<---- 
 *                                     Qsock
 *  
*/



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>

#include "queue.h"
#include "process_pkt.h"



/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000   
#define CLIENT 0
#define SERVER 1
#define PORT 55555

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

/* Define return values for io_timeout */
#define FDTAP_IN_RDY		0x01
#define FDSOCK_IN_RDY		0x02
#define FDTAP_OUT_OK		0x04
#define FDSOCK_OUT_OK		0x08
#define FDTAP_OUT_OVERRUN	0x10
#define FDSOCK_OUT_OVERRUN	0x20

int debug;
char *progname;


/**
 * Allocates or reconnects to a tun/tap device. The caller needs to reserve enough space in *dev.
 *
 * @param[out]	dev A pointer to the name of the tun/tap device 
 * @param[in]	flags An int which sets the type of the tun/tap device
 * @return		file descriptor
 *
 */
int tun_alloc(char *dev, int flags) {
	struct ifreq ifr;
	int fd, err;

	if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
		perror("Opening /dev/net/tun");
		return fd;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = flags;

	if (*dev) {
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	}

	if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
		perror("ioctl(TUNSETIFF)");
		close(fd);
		return err;
	}

	strcpy(dev, ifr.ifr_name);

	return fd;
}

/**
 * Read routine that checks for errors and exits if an error is returned
 *
 * @brief		Read n bytes from file descriptor
 * @param[in]	fd file descriptor to read from
 * @param[out]	buf buffer to save to
 * @param[in]	n number of bytes to read
 * @return		number of read bytes
 *
 */
int cread(int fd, char *buf, int n)
{
  
  int nread;

  if((nread=read(fd, buf, n))<0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**
 * Write routine that checks for errors and exits if an error is returned
 *
 * @brief		Write n bytes from file descriptor
 * @param[in]	fd file descriptor to write to
 * @param[in]	buf buffer to write from
 * @param[in]	n number of bytes to write
 * @return		number of written bytes
 * 
 */
int cwrite(int fd, char *buf, int n)
{
	int nwrite;

	if((nwrite=write(fd, buf, n))<0){
		perror("Writing data");
		exit(1);
	}
	return nwrite;
}


/**
 * Ensures we read exactly n bytes, and puts those into "buf"
 * (unless EOF, of course)
 *
 * @brief		read n bytes from a file descriptor
 * @param[in]	fd file descriptor
 * @param[out]	buf pointer where to write the data to
 * @param[in]	n number of bytes to read
 *
 */
int read_n(int fd, char *buf, int n)
{
	int nread, left = n;

	while(left > 0) {
		if ((nread = cread(fd, buf, left))==0){
			return 0;
		}else {
			left -= nread;
			buf += nread;
		}
	}
	return n;  
}

/**
 * Prints debugging stuff (doh!)
 *
 * @param[in] msg
 * 
 */
void do_debug(char *msg, ...)
{
	va_list argp; 
	if (debug) {
		va_start(argp, msg);
		vfprintf(stderr, msg, argp);
		va_end(argp);
	}
}

/**
 * Prints custom error messages on stderr
 * 
 * @param[in] *msg
 *
 */
void my_err(char *msg, ...) {

  va_list argp;
  
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}


/**
 * @var timeout
 * Wall time to next output event (tap or sock writing)
 * Used in select function.
 * 
 * @var  qtap_next_pkt_out
 * Wall time to the next output event to dequeue a packet
 * from Qtap queue. This dequeued packet has to be send through 
 * the tcp socket. If qtap_next_pkt_out.tv_sec = -1 then there is
 * not scheduled time loaded (Empty queue => no waiting packet to send) 
 * 
 * @var qsock_next_pkt_out
 * Wall time to the next output event to dequeue a packet
 * from Qsock queue. This dequeued packet has to be send through 
 * the tap device.	If qsock_next_pkt_out.tv_sec = -1 then there is
 * not scheduled time loaded (Empty queue => no waiting packet to send)
 *
 */
 
struct timeval timeout;
struct timeval qtap_next_pkt_out;
struct timeval qsock_next_pkt_out;

/**
 * @var static long int T 
 * 1/T is the packet rate (T in microseconds)
 * For T=500000 usec => T=0.5 msec => 2 packets/sec
 */
static long int T = 50000;

/**
 * 
 * @brief This function schedules filedes output events
 * 
 * This function synchronizes the output and input operations on tap and sock
 * file descriptors. 
 * 
 * Input operations are driven asynchronously by packet arrivals.
 * Output operations are driven synchronously by a timer which establishes
 * when a packet has to be send in order to cope with the selected packet 
 * rate (T variable).
 * 
 * Return value is an ORed value which signa ls which operation(s) has
 * to be performed:
 * 		- (ret_val & FDTAP_IN_RDY) != 0. A packet is waiting to be read on 
 *		  tap device. The action to be performed: read packet from tap and 
 * 		  enqueue it in Qtap.
 * 		- (ret_val & FDSOCK_IN_RDY) != 0. A packet is waiting to be read on 
 * 		  tcp socket. The action to be performed: read packet from socket
 * 		  and enqueue it in Qsock.	
 * 		- (ret_val & FDTAP_OUT_OK) != 0. A packet has to be send NOW on tap
 * 		  device. The action to be performed: Dequeue packet from Qsock and
 * 		  send it through tap device.
 * 		- (ret_val & FDSOCK_OUT_OK) != 0. A packet has to be send NOW on tcp
 * 		  socket. The action to be performed: Dequeue packet from Qtap and 
 * 		  send it through socket. 
 * 		- (ret_val & FDTAP_OUT_OVERRUN) !=0. A packet has to be send NOW
 * 		  through tap device, but tap device is no ready to be written. 
 * 		- (ret_val & FDSOCK_OUT_OVERRUN) !=0. A packet has to be send NOW 
 * 		  through socket, but socket is no ready to be written. 
 * 
 * 
 * 
 * 
 *                                  _________
 *                             ---->_________|O--->
 *                            |        Qtap         |
 *                   tap <--->|                     |<---> tcp socket
 *                   (fdtap)  |      __________     |       (fdsock)
 *                             <---O|__________<---- 
 *                                      Qsock
 *         
 */

int io_timeout (int fdtap, int fdsock) {
	fd_set readfds, writefds;

	/**
	 * @var remain_usec1 
	 * Remaining microseconds from now to the Qtap output event,
	 * just when a packet has to be dequeue from Qtap
	 * 
	 */
	long int remain_usec_1;
	/**
	 * @var remain_usec2 
	 * Remaining microseconds from now to the Qsock output event,
	 * just when a packet has to be dequeue from Qsock
	 * 
	 */
	long int remain_usec_2;

	struct timeval start_tv, stop_tv;
	int srv, nfds, which, return_value, use_null_timeout;
	
	do_debug("IO_TIMEOUT\n");
	gettimeofday(&start_tv,NULL);
	return_value = 0;

	/* Initialize the timeout data structure. */
	remain_usec_1 = (qtap_next_pkt_out.tv_sec - start_tv.tv_sec)*1000000 +
		(qtap_next_pkt_out.tv_usec - start_tv.tv_usec);
	remain_usec_2 = (qsock_next_pkt_out.tv_sec - start_tv.tv_sec)*1000000 +
		(qsock_next_pkt_out.tv_usec - start_tv.tv_usec);


    do_debug("qtap_next_pkt_out=%ld  qsock_next_pkt_out=%ld\n",
		qtap_next_pkt_out.tv_sec, qsock_next_pkt_out.tv_sec);

    do_debug("Schedule time for Qtap: %ld.%.6ld\n",
		qtap_next_pkt_out.tv_sec, qtap_next_pkt_out.tv_usec);

    do_debug("Schedule time for Qsock: %ld.%.6ld\n",
		qsock_next_pkt_out.tv_sec, qsock_next_pkt_out.tv_usec);

    do_debug("Now is: %ld.%.6ld\n", start_tv.tv_sec, start_tv.tv_usec);
	do_debug("remain_usec_1 is: %ld\n", remain_usec_1);
	do_debug("remain_usec_2 is: %ld\n", remain_usec_2);

	if (remain_usec_1 < 0) remain_usec_1 = 0;
	if (remain_usec_2 < 0) remain_usec_2 = 0;

	//Nor a qtap packet nor a qsock packet has been scheduled for output
	if (qtap_next_pkt_out.tv_sec == -1 && qsock_next_pkt_out.tv_sec == -1) {
		// There is no packet to be send, disable timout and wait only for input event
		use_null_timeout = 1;
	}

	//None qtap packet has been scheduled for output but yes for qsock
	if (qtap_next_pkt_out.tv_sec == -1 && qsock_next_pkt_out.tv_sec >= 0) {
		use_null_timeout = 0;
		timeout.tv_sec = 0;
		timeout.tv_usec = remain_usec_2;	
		which = 2;
	}

	//None qsock packet has been scheduled for output but yes for qtap
	if (qsock_next_pkt_out.tv_sec == -1 && qtap_next_pkt_out.tv_sec >= 0) {
		use_null_timeout = 0;
		timeout.tv_sec = 0;
		timeout.tv_usec = remain_usec_1;	
		which = 1;
	}

	if (qtap_next_pkt_out.tv_sec >= 0 && qsock_next_pkt_out.tv_sec >= 0) {
		use_null_timeout = 0;
		// Select minimum waiting time to schedule the next output event
    	if (remain_usec_1 < remain_usec_2) {
			timeout.tv_sec = 0;
			timeout.tv_usec = remain_usec_1;
			which = 1;		
		} else {
			timeout.tv_sec = 0;
			timeout.tv_usec = remain_usec_2;	
			which = 2;
		}
	}	

    do_debug("Remaining timeout: %ld\n", timeout.tv_sec*1000000 + timeout.tv_usec);
	// We are going to wait for an input event (tap or sock receives a packet)
	FD_ZERO (&readfds);
	FD_SET (fdtap, &readfds);
    FD_SET (fdsock, &readfds);
  	nfds = max(fdtap, fdsock);
	if (use_null_timeout) 
		// There are no packet in queues to be send. Wait for an input event forever
		srv = select (nfds + 1, &readfds, NULL, NULL, NULL);
	else
		// There is a packet scheduled to be send in timeout. Until timeout is reached
		// wait for an input packet 
  		srv = select (nfds + 1, &readfds, NULL, NULL, &timeout);
	if (FD_ISSET(fdtap, &readfds)) {
    	// A Packet has arrived from tap.
		// Check if there is already a packet scheduled to be sent, if not, schedule this one
		// Note that the first packet is scheduled to be sent BEFORE it is enqueued. 
		if (qtap_next_pkt_out.tv_sec == -1) {
			gettimeofday(&start_tv,NULL);
			qtap_next_pkt_out.tv_sec = start_tv.tv_sec;
			qtap_next_pkt_out.tv_usec = start_tv.tv_usec + T;
		}
		return_value = return_value | FDTAP_IN_RDY;
	}
	if (FD_ISSET(fdsock, &readfds)) {
    	// A packet has arrived from sock
		// Check if there is a packet scheduled to send, if not, schedule this one
		if (qsock_next_pkt_out.tv_sec == -1) {
			gettimeofday(&start_tv,NULL);
			qsock_next_pkt_out.tv_sec = start_tv.tv_sec;
			qsock_next_pkt_out.tv_usec = start_tv.tv_usec + T;
		}
		return_value = return_value | FDSOCK_IN_RDY;
	}
	// If srv is zero a timeout has occurred: A packet is ready to be send
    if (srv == 0) {
		// Now, we must output a packet
    	// First, check if write operation is not blocked on sock and tap filedes
		// To do this use select with timeout=0.
		FD_ZERO (&writefds);
		FD_SET (fdtap, &writefds);
    	FD_SET (fdsock, &writefds);
  		nfds = max(fdtap, fdsock);
		timeout.tv_sec = 0;
		timeout.tv_usec = 0;
  		srv = select (nfds + 1, NULL, &writefds, NULL, &timeout);
		// We use "which" variable to select the right filedes where we have to send. 
		if (which == 1) {      	
			if (FD_ISSET(fdsock, &writefds)) {
				// sock is ready to be written
                // Schedule next packet sending time in Qtap
				gettimeofday(&start_tv,NULL);
				qtap_next_pkt_out.tv_sec = start_tv.tv_sec;
				qtap_next_pkt_out.tv_usec = start_tv.tv_usec + T;
				do_debug("FDSOCK_OUT_OK in %d\n",start_tv.tv_sec*1000000 + start_tv.tv_usec );
				return_value = return_value | FDSOCK_OUT_OK;
			} else {
				// We have a problem: a packet has to be send through sock device
                // but fdsock write operation is blocked!!!
				return_value = return_value | FDSOCK_OUT_OVERRUN;				
			}
		}
		if (which == 2) {      	
			if (FD_ISSET(fdtap, &writefds)) {
				// Schedule next packet sending time
				gettimeofday(&start_tv,NULL);
				qsock_next_pkt_out.tv_sec = start_tv.tv_sec;
				qsock_next_pkt_out.tv_usec = start_tv.tv_usec + T;
				return_value = return_value | FDTAP_OUT_OK;
				do_debug("FDTAP_OUT_OK in %d\n",start_tv.tv_sec*1000000 + start_tv.tv_usec );
			} else {
				//A new packet has to be send through fdsock but write is blocked!!!
				return_value = return_value | FDTAP_OUT_OVERRUN;				
			}
		}

	}
	return return_value;
}

/**
 * Prints usage and exists
 *
 */
void usage(void)
{
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}




/**
 * The core of the program. Has the responsability of act accordingly to the
 * scheduler event and setting up the initial variables and structures
 * depending if it acts as a server or a client
 *
 * @param	argc An integer argument count of the command line arguments
 * @param	argv An argument vector of the command line arguments
 * @return	0
 */
int main(int argc, char *argv[])
{
	int tap_fd, option;
	int flags = IFF_TUN;
	char if_name[IFNAMSIZ] = "";
	int header_len = IP_HDR_LEN;
	int maxfd;
	uint16_t nread, nwrite, plength;
	char buffer[BUFSIZE];
	struct sockaddr_in local, remote;
	char remote_ip[16] = "";
	unsigned short int port = PORT;
	int sock_fd, net_fd, optval = 1;
	socklen_t remotelen;
	int cliserv = -1;    /* must be specified on cmd line */
	unsigned long int tap2net = 0, net2tap = 0;

 	progname = argv[0];
	
  
	/* Check command line options */
	while((option = getopt(argc, argv, "i:sc:p:uahd")) > 0){
		switch(option) {
		case 'd':
        	debug = 1;
        	break;
		case 'h':
			usage();
			break;
		case 'i':
			strncpy(if_name, optarg, IFNAMSIZ-1);
			break;
		case 's':
			cliserv = SERVER;
			break;
		case 'c':
			cliserv = CLIENT;
			strncpy(remote_ip, optarg,15);
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'u':
			flags = IFF_TUN;
			break;
		case 'a':
			flags = IFF_TAP;
			header_len = ETH_HDR_LEN;
			break;
		default:
			my_err("Unknown option %c\n", option);
			usage();
		}
	}

	argv += optind;
	argc -= optind;

	if (argc > 0) {
		my_err("Too many options!\n");
		usage();
	}

	if (*if_name == '\0') {
		my_err("Must specify interface name!\n");
		usage();
	} else if (cliserv < 0) {
		my_err("Must specify client or server mode!\n");
		usage();
	} else if ((cliserv == CLIENT)&&(*remote_ip == '\0')) {
		my_err("Must specify server address!\n");
		usage();
	}

 	/* initialize tun/tap interface */
	if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
		my_err("Error connecting to tun/tap interface %s!\n", if_name);
		exit(1);
	}

	do_debug("Successfully connected to interface %s\n", if_name);

	if ( (sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket()");
		exit(1);
	}


	if(cliserv==CLIENT) {
		/* Client, try to connect to server */

		/* assign the destination address */
		memset(&remote, 0, sizeof(remote));
		remote.sin_family = AF_INET;
		remote.sin_addr.s_addr = inet_addr(remote_ip);
		remote.sin_port = htons(port);

		/* connection request */
		if (connect(sock_fd, (struct sockaddr*) &remote, sizeof(remote)) < 0) {
			perror("connect()");
			exit(1);
		}

		net_fd = sock_fd;
		do_debug("CLIENT: Connected to server %s\n", inet_ntoa(remote.sin_addr));
    
	} else {
		/* Server, wait for connections */

		/* avoid EADDRINUSE error on bind() */
		if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
			perror("setsockopt()");
			exit(1);
		}

		memset(&local, 0, sizeof(local));
		local.sin_family = AF_INET;
		local.sin_addr.s_addr = htonl(INADDR_ANY);
		local.sin_port = htons(port);
		if (bind(sock_fd, (struct sockaddr*) &local, sizeof(local)) < 0) {
			perror("bind()");
			exit(1);
		}

		if (listen(sock_fd, 5) < 0){
			perror("listen()");
			exit(1);
		}

		/* wait for connection request */
		remotelen = sizeof(remote);
		memset(&remote, 0, remotelen);
		if ((net_fd = accept(sock_fd, (struct sockaddr*)&remote, &remotelen)) < 0) {
			perror("accept()");
			exit(1);
		}

		do_debug("SERVER: Client connected from %s\n", inet_ntoa(remote.sin_addr));
	}

	/* Create structures to keep packets */
	/** * @var Qsock @brief queue to save packets arriving from socket */
	pktqueue_t Qsock;
	queue_init(&Qsock, 100, "Qsock");

	/** @var Qtap @brief queue to save packets arriving from tap dev */         	
	pktqueue_t Qtap;
	queue_init(&Qtap, 100, "Qtap");

  	packet_t *packet;
	int j=0;
    
    // Disable schedule sending time on both queues 
	qtap_next_pkt_out.tv_sec = -1;
	qsock_next_pkt_out.tv_sec = -1;

	/** @var trigger_seq @brief is the sequence that triggered the mechanism */
	unsigned int trigger_seq = -1;

	packet_t *dupack;
	int in_backward_cc= -1;
	unsigned short pkt_count= 0;
	int i;
	char *ptr;

	while(1) {
		j=io_timeout (tap_fd,net_fd);
		if ( j & FDTAP_IN_RDY) {
			do_debug("Ready to read data in tap interface\n");
			// Allocate memory for new packet
			packet = (packet_t *) malloc(sizeof(packet_t));
			// Read packet from tap to the packet structure
			nread = cread(tap_fd, packet->data, BUFSIZE);
			packet->length = nread;
			tap2net++;
			do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);
			if (in_backward_cc == -3) pkt_count++; //Count packets
			// Enqueue packet in Qtap if its not the retransmission
			if (getTCPSeq(packet->data) == trigger_seq){
				free(packet);
				do_debug("Stop retransmission\n");
			} else if (enqueue_packet(&Qtap, packet) == 0) {
				//Queue full -> Drop packet
				free(packet);
			}
			if ((Qtap.fullness > 20) && (in_backward_cc == -1)) {
				trigger_seq= getTCPSeq(packet->data);
				do_debug("Backward Congestion initiation\n");
				do_debug("trigger_seq= %u\n", trigger_seq);
				in_backward_cc= -2;
			}
		}

		if ( j & FDSOCK_IN_RDY) {
			do_debug("Ready to read data in socket\n");
			// Allocate memory for new packet
			packet = (packet_t *) malloc(sizeof(packet_t));
			/* data from the network: read it.
			 * We need to read the length first, and then the packet */
			/* Read length */      
			nread = read_n(net_fd, (char *)&plength, sizeof(plength));      
			/* read packet */
			nread = read_n(net_fd, packet->data, ntohs(plength));
			packet->length = nread;			
			do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);
			// Enqueue packet in Qsock
			if (enqueue_packet(&Qsock, packet) == 0) {
				//Queue full -> Drop packet
				free(packet);
			}
		}


		if ( j & FDTAP_OUT_OK) {
			do_debug("Ready to write data to tap interface\n");
			if (in_backward_cc == -3) in_backward_cc = 0;
			//Time to send packet to tap
			if (in_backward_cc > -1) {
				if ((packet = dequeue_packet(&Qsock)) == NULL) {
					qsock_next_pkt_out.tv_sec = -1;
				} else {
					//Send ACK
					if (in_backward_cc == 0) {
						if (CheckPureTCPAck(packet->data) == 1) {
							// save this ack as a dupack ... Eps: pointer copy... warning!!!
							dupack = packet;
							in_backward_cc++;
						  	do_debug("Backward Congestion initiation\n");
							nwrite= cwrite(tap_fd, packet->data, packet->length);
						}
					//Send last DUPACK
					} else if (getACKSeq(packet->data) >= trigger_seq && trigger_seq != -1) {
						do_debug("Terminando cc: %u\n", getACKSeq(dupack->data));
						nwrite = cwrite(tap_fd, packet->data, packet->length);
						trigger_seq = -1;
						in_backward_cc = -1;
						pkt_count = 0;
						free(dupack);
						do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
					//Send DUPACKS
					} else {
						do_debug("Writing dupack: %u\n", getACKSeq(dupack->data));

						for (i= 0; i<pkt_count; i++) {
							ptr= create_dupack(dupack->data, (in_backward_cc*pkt_count)-pkt_count+i+1, getTimestampVal(packet->data));
							nwrite= cwrite(tap_fd, ptr, dupack->length);
						}
						i = 0;

						in_backward_cc++;
					}

				}

			}  else {
				//Try to dequeue packet from Qsock
				if ((packet = dequeue_packet(&Qsock)) == NULL) {
					//Queue is empty, disable next sending time until new packet arrives
					qsock_next_pkt_out.tv_sec = -1;
				}else {
					if (in_backward_cc == -2) in_backward_cc = -3; //Wait for the return ACK to count packets
					nwrite = cwrite(tap_fd, packet->data, packet->length);
					if (in_backward_cc == -1) free(packet);
					do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
				}
			}
		}


		if ( j & FDSOCK_OUT_OK) {
			do_debug("Ready to write data to socket\n");
			//Time to send packet to sock
			//Try to dequeue packet from Qtap
			if ((packet = dequeue_packet(&Qtap)) == NULL) {
				//Queue is empty, disable next sending time until new packet arrives
				qtap_next_pkt_out.tv_sec = -1;
			} else {
				plength = htons(packet->length);
      			nwrite = cwrite(net_fd, (char *)&plength, sizeof(plength));
				nwrite = cwrite(net_fd, packet->data, packet->length);
				free(packet);
				do_debug("TAP2NET %lu: Written %d bytes to the socket\n", tap2net, nwrite);
			}
		}
	}  
	return(0);
}
