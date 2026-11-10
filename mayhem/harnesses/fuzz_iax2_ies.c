/* IAX2 information-element parser (channels/iax2/parser.c), as run on every received IAX2 frame. */
#include "asterisk.h"
#include <stdint.h>
#include <string.h>
#include "asterisk/config.h"
#include "iax2/include/parser.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct iax_ies ies;
	unsigned char *buf;

	if (size > 4096) {
		return -1;
	}
	/* The IEs hold unterminated string pointers into the receive buffer, which chan_iax2 reads
	 * into a larger zeroed buffer; keep one NUL past the datagram. */
	buf = ast_calloc(1, size + 1);
	memcpy(buf, data, size);
	iax_parse_ies(&ies, buf, (int) size);
	ast_variables_destroy(ies.vars);
	ast_free(buf);
	return 0;
}
