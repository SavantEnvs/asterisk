/* STUN message parser (main/stun.c), as fed from the RTP socket. */
#include "asterisk.h"
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include "asterisk/stun.h"

static int count_attr(struct stun_attr *attr, void *arg)
{
	(*(int *)arg)++;
	return 0;
}

/* ast_stun_handle_packet() NUL-terminates past the end of the message (see the XXX note in
 * main/stun.c); its callers read into a buffer larger than the datagram. The harness hands it an
 * exact-size copy plus one byte, which is stricter than production. */
static void handle(const uint8_t *data, size_t size, stun_cb_f *cb, int *count)
{
	struct sockaddr_in src = { .sin_family = AF_INET };
	unsigned char *pkt = ast_calloc(1, size + 1);

	memcpy(pkt, data, size);
	ast_stun_handle_packet(-1, &src, pkt, size, cb, count);
	ast_free(pkt);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	int count = 0;

	/* ast_stun_request() reads responses with a callback (stun_get_mapped), res_rtp_asterisk.c
	 * passes none; the parser rewrites the packet, so each call gets its own copy. */
	handle(data, size, count_attr, &count);
	handle(data, size, NULL, NULL);
	return 0;
}
