/** 
 * @file	queue.c
 * @authors	Carlos Manso
 * @date	June 2016
 * @license GNU GPL	v3
 * @brief	Multiple functions to deal with a circular queue of packets
 *
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <math.h> /*ceilf*/
#include <string.h>
#include <limits.h>
#include <stdlib.h> /* exit() */

#include "queue.h"

float a = 0.5;

/**
 * Exponential Weighted Moving Average of the queue
 * 
 * @brief	Calculates the EWMA of the queue
 * @param	a weight
 * @param	ewma_last last value of EWMA
 * @param	Qcurrent fullness of the queue
 * @return	int ewma
 *
 */
static inline float ewma(float a, float ewma_last, int Qcurrent ) {
	return (1-a)*ewma_last + a*Qcurrent;
}

/**
 * Checks if a pkqueue_t is empty
 *
 * @brief	Checks if the queue is empty
 * @param	p pktqueue_t
 * @return	1 if true 0 if false
 *
 */
int isempty(pktqueue_t *p) {
	if (p->front == p->rear) return 1;
	else return 0;
}

/**
 * Prints the current state of the queue, the buffer size, the front, rear, fullness, smooth fullnes and fullness in bytes
 * 
 * @brief	Prints the current state of the queue
 * @param	p Packetqueue
 * @param	ev TODO
 *
 */
void print_queue(pktqueue_t *p, char ev) {

	struct timeval now;
	gettimeofday(&now,NULL);
	do_debug("%s %c (%ld.%.6ld): buffer_size=%ld, front=%d, rear=%d, fullness=%d, sfullness=%.2f, bfullness=%d\n",
				p->Qname, ev, now.tv_sec, now.tv_usec, p->buffer_size, p->front, p->rear, p->fullness, 
				p->sfullness, p->bfullness);
	if(isempty(p)) {
		do_debug("%s: Queue empty\n",p->Qname);
	} 
}


/**
 * Initializes pktqueue_t structure values.
 * 
 * @brief	Initializes a pktqueue_t
 * @param	p pktqueue_t to initialize
 * @param	queuesize Desired size of the queue
 * @param	Qname Desired name of the queue
 *
 */
void queue_init(pktqueue_t *p, int queuesize, char *Qname) {
	strcpy(p->Qname,Qname);
    p->buffer_size = queuesize;
	p->fullness=0;
	p->sfullness=0;
	p->bfullness=0;
	p->rear=p->front=0;
	p->arr = (packet_t **) malloc((p->buffer_size)*sizeof(packet_t *));
    do_debug("Initializing packet queue %s\n", Qname);
    print_queue(p,'i');
}

/**
 * Enqueues a packet_t in a pktqueue_t and updates it's data
 * 
 * @brief	Enqueues a packet_t
 * @param	p Queue to enqueue the packet
 * @param	pkt Packet to enqueue
 * @return	1 if it succeeded 0 if it didn't
 * 
 */
int enqueue_packet(pktqueue_t *p, packet_t *pkt) {
	int t;
    do_debug("%s: enqueue_packet\n",p->Qname);
	t = (p->rear+1)%p->buffer_size;
	if (t == p->front) {
		do_debug("\n%s: Queue Overflow\n", p->Qname);
		return 0;
	}
	else {
		p->rear=t;
		p->arr[p->rear]= pkt;
		p->fullness++;
		p->sfullness = ewma(a, p->sfullness, p->fullness);
        p->bfullness+=pkt->length;
		print_queue(p, 'e'); 
		return 1;
	}
}


/**
 * Gets the pointer to the current packet in the queue
 * 
 * @brief	Reads a packet from a pktqueue_t
 * @param	p Queue
 * @return	Read packet
 *
 */
packet_t * read_packet(pktqueue_t *p)
{
	if(isempty(p)){
		do_debug("\n%s: Queue underflow??\n", p->Qname);
		return NULL;
	}
	else {
		return (p->arr[p->front]);
	}

}

/**
 * Gets the pointer to the current packet_t in a pktqueue_t and updates it's data
 * 
 * @brief	Dequeue a packet from a pktqueue_t
 * @param	p Queue
 * @return	Dequeued packet
 *
 */
packet_t * dequeue_packet(pktqueue_t *p) {
    do_debug("%s: dequeue_packet\n", p->Qname);
	if (isempty(p)) {
		do_debug("\n%s: Queue Underflow\n",p->Qname);
		return NULL;
	}
	else {
		p->front=(p->front + 1)%p->buffer_size;
	 	p->fullness--;
		p->sfullness = ewma(a, p->sfullness, p->fullness);
        p->bfullness-=(p->arr[p->front])->length; 
		print_queue(p, 'd'); 
		return(p->arr[p->front]);
	}
}


