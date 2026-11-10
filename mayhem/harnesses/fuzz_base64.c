/* base64 and base64url decode/encode of text carried in SIP/HTTP/config values (main/utils.c). */
#include "asterisk.h"
#include <stdint.h>
#include <string.h>
#include "asterisk/utils.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	/* builds the base64 lookup tables */
	ast_utils_init();
	return 0;
}

/* Input: [selector][limit][payload ...]. selector & 7 picks the entry point, selector & 8 turns on
 * line breaks for the *_full encoders, and (selector >> 6) is the high bits of the output limit
 * (limit + 256 * (selector >> 6) + 1, in 1..1024), so truncation at every length is reachable.
 * The payload is copied into an exact-size heap buffer; for the string entry points it is
 * NUL-terminated, as they take C strings. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char enc[1024];
	unsigned char dec[1024];
	unsigned char sel;
	int max;
	size_t len;
	char *buf, *str;

	if (size < 2 || size > 512) {
		return -1;
	}
	sel = data[0];
	max = data[1] + 256 * (sel >> 6) + 1;
	len = size - 2;
	buf = ast_malloc(len + 1);
	memcpy(buf, data + 2, len);
	buf[len] = '\0';

	switch (sel & 7) {
	case 0:
		ast_base64decode(dec, buf, max);
		break;
	case 1:
		ast_base64encode_full(enc, (unsigned char *) buf, (int) len, max, sel & 8);
		break;
	case 2:
		ast_base64url_decode(dec, buf, max);
		break;
	case 3:
		ast_base64url_encode_full(enc, (unsigned char *) buf, (int) len, max, sel & 8);
		break;
	case 4:
		str = ast_base64decode_string(buf);
		ast_free(str);
		break;
	case 5:
		str = ast_base64encode_string(buf);
		ast_free(str);
		break;
	case 6:
		str = ast_base64url_decode_string(buf);
		ast_free(str);
		break;
	default:
		str = ast_base64url_encode_string(buf);
		ast_free(str);
		break;
	}
	ast_free(buf);
	return 0;
}
