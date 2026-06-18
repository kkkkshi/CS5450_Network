#include "gbn.h"

#define HEADERLEN (sizeof(gbnhdr) - DATALEN)
#define MAX_WIN   64

state_t s;

uint16_t checksum(uint16_t *buf, int nwords)
{
	uint32_t sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

/* handler does nothing, it's just here so SIGALRM breaks recvfrom */
static void sig_handler(int sig){
	(void)sig;
}

static int make_packet(gbnhdr *p, uint8_t type, uint8_t seqnum,
                       const char *data, int datalen){
	int len;

	memset(p, 0, sizeof(*p));
	p->type     = type;
	p->seqnum   = seqnum;
	p->checksum = 0;
	if (data != NULL && datalen > 0)
		memcpy(p->data, data, datalen);

	len = (int)HEADERLEN + (data != NULL ? datalen : 0);
	p->checksum = checksum((uint16_t *)p, (len + 1) / 2);
	return len;
}

static int is_corrupt(gbnhdr *p, int len){
	return checksum((uint16_t *)p, (len + 1) / 2) != 0;
}

int gbn_socket(int domain, int type, int protocol){

	/*----- Randomizing the seed. This is used by the rand() function -----*/
	srand((unsigned)time(0));

	s.state   = CLOSED;
	s.seqnum  = 0;
	s.winsize = 1;

	signal(SIGALRM, sig_handler);
	siginterrupt(SIGALRM, 1);

	return socket(domain, type, protocol);
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen){
	return bind(sockfd, server, socklen);
}

int gbn_listen(int sockfd, int backlog){
	s.state = CLOSED;
	return 0;
}

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen){
	gbnhdr packet, ack;
	int r, acklen;

	/* wait for a SYN */
	while (1) {
		memset(&packet, 0, sizeof(packet));
		r = maybe_recvfrom(sockfd, (char *)&packet, sizeof(packet), 0, client, socklen);
		if (r < 0)
			return -1;
		if (is_corrupt(&packet, r) || packet.type != SYN)
			continue;
		break;
	}

	/* remember the client so we know where to send acks later */
	memcpy(&s.peer, client, *socklen);
	s.peerlen = *socklen;

	acklen = make_packet(&ack, SYNACK, 0, NULL, 0);
	maybe_sendto(sockfd, &ack, acklen, 0, client, *socklen);

	s.state  = ESTABLISHED;
	s.seqnum = 0;
	return sockfd;
}

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){
	gbnhdr syn, resp;
	int synlen, r, tries;

	memcpy(&s.peer, server, socklen);
	s.peerlen = socklen;

	synlen   = make_packet(&syn, SYN, 0, NULL, 0);
	s.state  = SYN_SENT;

	/* send SYN, wait for SYNACK, retry a few times on timeout */
	for (tries = 0; tries < 5; tries++) {
		maybe_sendto(sockfd, &syn, synlen, 0, server, socklen);

		alarm(TIMEOUT);
		memset(&resp, 0, sizeof(resp));
		r = maybe_recvfrom(sockfd, (char *)&resp, sizeof(resp), 0, NULL, NULL);
		alarm(0);

		if (r < 0)
			continue;
		if (is_corrupt(&resp, r))
			continue;
		if (resp.type == SYNACK) {
			s.state  = ESTABLISHED;
			s.seqnum = 0;
			return 0;
		}
		if (resp.type == RST) {
			s.state = CLOSED;
			return -1;
		}
	}

	s.state = CLOSED;
	return -1;
}

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){
	int npackets = ((int)len + DATALEN - 1) / DATALEN;
	int base = 0;
	int next = 0;
	int tries = 0;

	while (base < npackets) {
		gbnhdr ack;
		int r, advance;

		/* fill up the window */
		while (next < base + s.winsize && next < npackets) {
			gbnhdr pkt;
			int off   = next * DATALEN;
			int chunk = ((int)len - off > DATALEN) ? DATALEN : ((int)len - off);
			int plen  = make_packet(&pkt, DATA, (uint8_t)(s.seqnum + next),
			                        (const char *)buf + off, chunk);
			maybe_sendto(sockfd, &pkt, plen, 0,
			             (struct sockaddr *)&s.peer, s.peerlen);
			next++;
		}

		alarm(TIMEOUT);
		memset(&ack, 0, sizeof(ack));
		r = maybe_recvfrom(sockfd, (char *)&ack, sizeof(ack), 0, NULL, NULL);
		alarm(0);

		if (r < 0) {
			/* timed out: slow down to go-back-1 and resend the window */
			if (++tries >= 5)
				return -1;
			s.winsize = 1;
			next = base;
			continue;
		}
		if (is_corrupt(&ack, r) || ack.type != DATAACK)
			continue;

		/* cumulative ack tells us how far the receiver got */
		advance = (uint8_t)(ack.seqnum - (uint8_t)(s.seqnum + base));
		if (advance > 0 && advance <= next - base) {
			base += advance;
			tries = 0;
			if (s.winsize < MAX_WIN)
				s.winsize *= 2;
		}
	}

	s.seqnum += npackets;
	return len;
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){
	gbnhdr pkt, ack;
	struct sockaddr_in from;
	socklen_t fromlen;
	int r, plen, datalen;

	while (1) {
		memset(&pkt, 0, sizeof(pkt));

		/* recv into a local addr - don't write the shared state on every packet */
		fromlen = sizeof(from);
		r = maybe_recvfrom(sockfd, (char *)&pkt, sizeof(pkt), 0,
		                   (struct sockaddr *)&from, &fromlen);
		if (r < 0)
			return -1;

		if (!is_corrupt(&pkt, r) && pkt.type == FIN) {
			plen = make_packet(&ack, FINACK, 0, NULL, 0);
			maybe_sendto(sockfd, &ack, plen, 0,
			             (struct sockaddr *)&s.peer, s.peerlen);
			s.state = FIN_RCVD;
			return 0;
		}

		/* SYNACK got lost, sender is retrying the SYN */
		if (!is_corrupt(&pkt, r) && pkt.type == SYN) {
			plen = make_packet(&ack, SYNACK, 0, NULL, 0);
			maybe_sendto(sockfd, &ack, plen, 0,
			             (struct sockaddr *)&s.peer, s.peerlen);
			continue;
		}

		/* bad or out-of-order packet: drop it, re-ack what we have */
		if (is_corrupt(&pkt, r) || pkt.type != DATA || pkt.seqnum != s.seqnum) {
			plen = make_packet(&ack, DATAACK, s.seqnum, NULL, 0);
			maybe_sendto(sockfd, &ack, plen, 0,
			             (struct sockaddr *)&s.peer, s.peerlen);
			continue;
		}

		/* the one we wanted */
		datalen = r - (int)HEADERLEN;
		memcpy(buf, pkt.data, datalen);
		s.seqnum++;
		plen = make_packet(&ack, DATAACK, s.seqnum, NULL, 0);
		maybe_sendto(sockfd, &ack, plen, 0,
		             (struct sockaddr *)&s.peer, s.peerlen);
		return datalen;
	}
}

int gbn_close(int sockfd){
	gbnhdr fin, resp;
	int finlen, r, tries;

	/* receiver already handled the FIN inside gbn_recv */
	if (s.state == FIN_RCVD || s.state == CLOSED) {
		s.state = CLOSED;
		return close(sockfd);
	}

	finlen  = make_packet(&fin, FIN, 0, NULL, 0);
	s.state = FIN_SENT;

	for (tries = 0; tries < 5; tries++) {
		maybe_sendto(sockfd, &fin, finlen, 0,
		             (struct sockaddr *)&s.peer, s.peerlen);

		alarm(TIMEOUT);
		memset(&resp, 0, sizeof(resp));
		r = maybe_recvfrom(sockfd, (char *)&resp, sizeof(resp), 0, NULL, NULL);
		alarm(0);

		if (r < 0)
			continue;
		if (is_corrupt(&resp, r))
			continue;
		if (resp.type == FINACK)
			break;
	}

	s.state = CLOSED;
	return close(sockfd);
}

ssize_t maybe_recvfrom(int  s, char *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen){

	/*----- Packet not lost -----*/
	if (rand() > LOSS_PROB*RAND_MAX){


		/*----- Receiving the packet -----*/
		int retval = recvfrom(s, buf, len, flags, from, fromlen);

		/*----- Packet corrupted -----*/
		if (rand() < CORR_PROB*RAND_MAX){
			/*----- Selecting a random byte inside the packet -----*/
			int index = (int)((len-1)*rand()/(RAND_MAX + 1.0));

			/*----- Inverting a bit -----*/
			char c = buf[index];
			if (c & 0x01)
				c &= 0xFE;
			else
				c |= 0x01;
			buf[index] = c;
		}

		return retval;
	}
	/*----- Packet lost -----*/
	return(len);  /* Simulate a success */
}

ssize_t maybe_sendto(int  s, const void *buf, size_t len, int flags, \
                     const struct sockaddr *to, socklen_t tolen){

    char *buffer = malloc(len);
    memcpy(buffer, buf, len);


    /*----- Packet not lost -----*/
    if (rand() > LOSS_PROB*RAND_MAX){
        /*----- Packet corrupted -----*/
        if (rand() < CORR_PROB*RAND_MAX){

            /*----- Selecting a random byte inside the packet -----*/
            int index = (int)((len-1)*rand()/(RAND_MAX + 1.0));

            /*----- Inverting a bit -----*/
            char c = buffer[index];
            if (c & 0x01)
                c &= 0xFE;
            else
                c |= 0x01;
            buffer[index] = c;
        }

        /*----- Sending the packet -----*/
        int retval = sendto(s, buffer, len, flags, to, tolen);
        free(buffer);
        return retval;
    }
    /*----- Packet lost -----*/
    else
        return(len);  /* Simulate a success */
}
