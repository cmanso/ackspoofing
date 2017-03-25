/** 
 * @file	queue.h
 * @authors	Carlos Manso
 * @date	June 2016
 * @license GNU GPL	v3
 * @brief	Multiple functions to deal with a circular queue of packets
 *
 */
#include <stdint.h>

#undef max
#define max(x,y) ((x) > (y) ? (x) : (y))
#undef min
#define min(x,y) ((x) < (y) ? (x) : (y))

/**
 * Packet structure of 1500 bytes maximum with timing support and length control
 *
 * @brief	Packet structure with timing support
 */
typedef struct packet_t {
    int  length;				/**< length of the packet */
	struct timeval ptimein;		/**< timeval structure used for unenqueuing */
	uint8_t data[1500];			/**< pointer to the actual packet data */
} packet_t;


/**
 * Circular buffer of packet_t structures
 *
 * @brief	packet_t circular buffer
 */
typedef struct {
	packet_t **arr;
	char Qname[10];		/**< name of the queue */
	long buffer_size;	/**< size of the queue */
	int rear;			/**< rear position */
	int front;			/**< front position */
	int fullness;		/**< fullnes in number of packets */
	float sfullness;	/**< smooth fullness of packets */
    int bfullness;		/**< fullness in bytes */
} pktqueue_t;

int isempty(pktqueue_t *p);
void queue_init(pktqueue_t *p, int queuesize, char *Qname);
int enqueue_packet(pktqueue_t *p, packet_t *pkt);
packet_t *read_packet(pktqueue_t *p);
packet_t * dequeue_packet(pktqueue_t *p);
static inline float ewma(float, float, int);
