/** 
 * @file	process_pkt.h
 * @authors	Carlos Manso
 * @date	June 2016
 * @license GNU GPL	v3
 * @brief   Multiple functions to deal with packets
 *
 */

#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>    //memset
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<sys/socket.h>
#include<arpa/inet.h>

/**
 * Structure made for sending the Timestamp TCP option
 * 
 * @brief	Structure for the timestamp TCP option
 * @see		https://tools.ietf.org/html/rfc1323
 * @see		https://tools.ietf.org/html/rfc7323
 * 
 */
struct tshdr{
	uint8_t pad1;	/**< padding =0 */
	uint8_t pad2;	/**< padding =0 */
	uint8_t ok;		/**< Option Kind =8 */
	uint8_t ol;		/**< Option Length =sizeof(struct tshdr) */
	uint32_t sts;	/**< Sender TimeStamp */
	uint32_t ets;	/**< Echo TimeStamp */
} __attribute__((__packed__));


/**
 * Structure needed for the TCP checksum calculation
 * 
 * @brief Structure needed for the TCP checksum calculation
 *
 */
struct pseudo_header
{
	u_int32_t source_address;	/**< IP address of the source */
	u_int32_t dest_address;		/**< IP adress of the destination */
	u_int8_t placeholder;		/**< Reserverd, 0 */
	u_int8_t protocol;			/**< Protocol, 6 if TCP */
	u_int16_t tcp_length;		/**< Byte length of the whole TCP packet */
};

 
int getACKSeq(unsigned char* buffer);
int getTCPSeq(unsigned char *buffer);
int CheckPureTCPAck(unsigned char* buffer); 
uint32_t getTimestampVal(unsigned char* buffer);
void hexDump(void *addr, int len);
unsigned short csum(unsigned short *ptr,int nbytes);
unsigned char* create_dupack(unsigned char *pkt, int plus, uint32_t timestamp);
void debug_packet(unsigned char* Buffer, int Size);
