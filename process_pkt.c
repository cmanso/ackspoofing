/** 
 * @file	process_pkt.c
 * @authors	Carlos Manso
 * @date	June 2016
 * @license GNU GPL	v3
 * @brief   Multiple functions to deal with packets
 *
 */

#include "process_pkt.h" 


/**
 * @brief	Check if the TCP package is a pure ACK
 * @param	buffer Pointer to the TCP package
 * @return	1 if true 0 if false
 *
 */
int CheckPureTCPAck(unsigned char* buffer)
{
    unsigned short iphdrlen;
	unsigned int payload_size = 0;
    struct iphdr *iph = (struct iphdr*)buffer;



	if (iph->protocol == 6) {
    	iphdrlen =iph->ihl*4;
		struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen);
		if ((unsigned int)tcph->ack == 0) return 0;
		if ((unsigned int)tcph->urg == 1) return 0;
		if ((unsigned int)tcph->psh == 1) return 0;
		if ((unsigned int)tcph->rst == 1) return 0;
		if ((unsigned int)tcph->syn == 1) return 0;
		if ((unsigned int)tcph->fin == 1) return 0;
		//if ((unsigned int)tcph->cwr == 1) return 0;
		//if ((unsigned int)tcph->ece == 1) return 0;

		payload_size = ntohs(iph->tot_len)-(((unsigned int)(iph->ihl))*4)-(unsigned int)tcph->doff*4;		
		if (payload_size == 0) 
			return 1;
	}
	return 0; 
}


/**
 * @brief	Returns the ACK sequence
 * @param	buffer Pointer to the TCP package
 * @return	ACK sequence or -1 if it isn't an ACK
 *
 */
int getACKSeq(unsigned char* buffer)
{
	unsigned short iphdrlen;
	struct iphdr *iph= (struct iphdr *) buffer;
	iphdrlen= iph->ihl*4;

	struct tcphdr *tcph= (struct tcphdr*) (buffer + iphdrlen);
	if (tcph->ack == 1){
		return ntohl(tcph->ack_seq);
	}
	else{
		return -1;
	}
} 

/**
 * @brief	Returns the TCP sequence
 * @param	buffer Pointer to the TCP package
 * @return	TCP sequence number
 *
 */
int getTCPSeq(unsigned char *buffer)
{
	unsigned short iphdrlen;
	struct iphdr *iph= (struct iphdr *) buffer;
	iphdrlen= iph->ihl*4;

	struct tcphdr *tcph= (struct tcphdr*) (buffer + iphdrlen);
	return ntohl(tcph->seq);

}


/**
 * @brief	Returns the Timestamp Val
 * @param	buffer Pointer to the TCP package
 * @return	Timestamp val
 *
 */
uint32_t getTimestampVal(unsigned char* buffer)
{
	unsigned short iphdrlen;
	struct iphdr *iph= (struct iphdr *) buffer;
	iphdrlen= iph->ihl*4;

	struct tshdr *tsh= (struct tshdr*) (buffer + iphdrlen + sizeof(struct tcphdr));
	return ntohl(tsh->sts);
}

/**
 * @brief	Prints the hexadecimal dump of a memory segment 
 * @param	addr Pointer to the start of the segment
 * @param	len Length of the segment
 *
 */
void hexDump(void *addr, int len)
{
	int i;
	unsigned char buff[17];
	unsigned char *pc = (unsigned char*)addr;

	if (len == 0) {
		do_debug("  ZERO LENGTH\n");
		return;
	}
	if (len < 0) {
		do_debug("  NEGATIVE LENGTH: %i\n",len);
		return;
	}

	// Process every byte in the data.
	for (i = 0; i < len; i++) {
		// Multiple of 16 means new line (with line offset).

		if ((i % 16) == 0) {
			// Just don't print ASCII for the zeroth line.
			if (i != 0) {
				do_debug("  %s\n", buff);
			}
			// Output the offset.
			do_debug("  %04x ", i);
		}

		// Now the hex code for the specific character.
		do_debug(" %02x", pc[i]);

		// And store a printable ASCII character for later.
		if ((pc[i] < 0x20) || (pc[i] > 0x7e))
			buff[i % 16] = '.';
		else
            buff[i % 16] = pc[i];
		buff[(i % 16) + 1] = '\0';
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0) {
		do_debug("   ");
		i++;
	}

	// And print the final ASCII bit.
	do_debug ("  %s\n", buff);
}

/**
 * Calculates the 16 bit one's complement of the one's complement sum of all 16-bit words in the header and text.
 * The checksum field of the header must be 0 prior to the calculation
 * 
 * @brief	Calculate the IP/TCP checksum
 * @param	ptr pointer at the beginning of the header
 * @param	nbytes number of bytes of the whole package
 * @return	Checksum
 *
 */
unsigned short csum(unsigned short *ptr, int nbytes)
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
     
    return(answer);
}


/**
 * @brief	Prints the IP, TCP and TCP-TS fields as well as the hexadecimal dump
 * @param	Buffer pointer at the beginning of the package
 * @param	Size size of the package
 *
 */
void debug_packet(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;


    struct tcphdr *tcph=(struct tcphdr*) (Buffer + 20);
	struct tshdr *tsh= (struct tshdr*) (Buffer + sizeof(struct iphdr)+ sizeof(struct tcphdr));
	struct sockaddr_in source,dest;
	  
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;


    do_debug("\n\n***********************IP Packet*************************\n");
    do_debug("\n");
    do_debug("IP Header\n");
    do_debug("   |-IP Version        : %d\n",(unsigned int)iph->version);
    do_debug("   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    do_debug("   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    do_debug("   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    do_debug("   |-Identification    : %d\n",ntohs(iph->id));
    do_debug("   |-TTL      : %d\n",(unsigned int)iph->ttl);
    do_debug("   |-Protocol : %d\n",(unsigned int)iph->protocol);
    do_debug("   |-Checksum : %d\n",ntohs(iph->check));
    do_debug("   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
    do_debug("   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
    do_debug("\n\n***********************TCP Packet*************************\n");    
    do_debug("\n");
    do_debug("TCP Header\n");
    do_debug("   |-Source Port      : %u\n",ntohs(tcph->source));
    do_debug("   |-Destination Port : %u\n",ntohs(tcph->dest));
    do_debug("   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    do_debug("   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    do_debug("   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //fprintf(logfile,"   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //fprintf(logfile,"   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    do_debug("   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    do_debug("   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    do_debug("   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    do_debug("   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    do_debug("   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    do_debug("   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    do_debug("   |-Window         : %d\n",ntohs(tcph->window));
    do_debug("   |-Checksum       : %d\n",ntohs(tcph->check));
    do_debug("   |-Urgent Pointer : %d\n",tcph->urg_ptr);
	do_debug("   |-length: %i\n", Size);
	do_debug("   |-pad1:         : %d\n", tsh->pad1);
	do_debug("   |-pad2:         : %d\n", tsh->pad2);
	do_debug("   |-ok:         : %d\n", tsh->ok);
	do_debug("   |-ol:         : %d\n", tsh->ol);
	do_debug("   |-TSval:         : %lu\n", (unsigned long)ntohl(tsh->sts));
	do_debug("   |-TSecr:         : %lu\n", (unsigned long)ntohl(tsh->ets));


    do_debug("\n");
    do_debug("\n###########################################################\n");

    hexDump (Buffer, Size);
    do_debug("\n###########################################################\n");
}


/**
 * Creates a pure ACK of a given package changing the TCP-timestamp by (+ 23 + 6*plus) and the IP-id by +plus while
 * recalculates the IP and TCP checksums
 * 
 * @brief	Creates a modified ACK package
 * @param	pkt pointer at the beginning of the IP package
 * @param	plus n of actual dupACK
 * @return	pointer at the beginning of the new IP package
 *
 */
unsigned char* create_dupack(unsigned char *pkt, int plus, uint32_t timestamp)
{
	//create pointer structures to pkt
	struct iphdr *ip= (struct iphdr*)pkt;
	struct tcphdr *tcp= (struct tcphdr*) (pkt + sizeof(struct iphdr));
	struct tshdr *ts= (struct tshdr*) (pkt + sizeof(struct iphdr)
										+  sizeof(struct tcphdr));

	//create pointer structures to dpkt and copy the values to change just what we need
	int psize= sizeof(struct iphdr) + sizeof(struct tcphdr)
			 + sizeof(struct tshdr);
	char *dpkt= malloc(psize);
	memset (dpkt, 0, psize);
	struct iphdr *dip = (struct iphdr*) dpkt;
	struct tcphdr *dtcp = (struct tcphdr*) (dpkt + sizeof(struct iphdr));
	struct tshdr *dts = (struct tshdr*) (dpkt + sizeof(struct iphdr)
					 + sizeof(struct tcphdr));
	memcpy(dip, ip, sizeof(struct iphdr));

	//change dpkt-ip values
    dip->id= htons(ntohs(ip->id) + plus);	//Id of this packet
    dip->check = 0;					//Checksum, Set to 0 before calculating it
	dip->check = csum ((unsigned short *) dpkt, psize);	//IP checksum

	//do_debug("plus: %i, ID: %lu\n", plus, dip->id);

	memcpy(dtcp, tcp, sizeof(struct tcphdr));
	memcpy(dts, ts, sizeof(struct tshdr));

	//pseudo tcp header needed to calculate tcp checksum
	struct pseudo_header psh;
    psh.source_address = dip->saddr;
    psh.dest_address = dip->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr) + sizeof(struct tshdr));

	//change dpkt-tcp values
    dtcp->check = 0;	//leave checksum 0 now, filled later by pseudo header

	//change dpkt-ts values
	dts->sts= htonl(timestamp);

	//build pseudogram and calculate checksum
	char *pseudogram;
	int pseudosize= sizeof(struct pseudo_header) + sizeof(struct tcphdr)
				  + sizeof(struct tshdr);
    pseudogram = malloc(pseudosize);
    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , dtcp , sizeof(struct tcphdr));
	memcpy(pseudogram + sizeof(struct pseudo_header) + sizeof(struct tcphdr),
			dts,
			sizeof(struct tshdr));
	dtcp->check = csum( (unsigned short*) pseudogram , pseudosize);

	return (char *)dpkt;
}





