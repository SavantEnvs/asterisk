/* String/argument utilities that parse network- and config-supplied text: URI coding,
 * ast_strsep, escape handling, argument splitting, caller ID, JSON, sockaddr and ACL. */
#include "asterisk.h"
#include <stdint.h>
#include <string.h>
#include "asterisk/utils.h"
#include "asterisk/strings.h"
#include "asterisk/app.h"
#include "asterisk/callerid.h"
#include "asterisk/json.h"
#include "asterisk/netsock2.h"
#include "asterisk/acl.h"

/* Input: [selector][payload ...]. The payload is copied into an exact-size, NUL-terminated heap
 * buffer, as every one of these functions takes a C string. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char out[512];
	char num2[512];
	struct ast_flags spec = { 0 };
	char *buf, *s, *tok;
	char *argv[32];
	char *name, *num;
	size_t len;

	if (size < 1 || size > 1024) {
		return -1;
	}
	len = size - 1;
	buf = ast_malloc(len + 1);
	memcpy(buf, data + 1, len);
	buf[len] = '\0';

	switch (data[0] % 8) {
	case 0:
		ast_uri_decode(buf, spec);
		break;
	case 1:
		ast_uri_encode(buf, out, sizeof(out), spec);
		break;
	case 2:
		ast_unescape_c(buf);
		break;
	case 3:
		s = buf;
		while ((tok = ast_strsep(&s, ',', AST_STRSEP_ALL))) {
			char *t2 = tok;
			while (ast_strsep(&t2, '=', AST_STRSEP_STRIP)) {
			}
		}
		break;
	case 4:
		__ast_app_separate_args(buf, ',', data[0] & 0x10, argv, 32);
		break;
	case 5:
		ast_callerid_split(buf, out, sizeof(out), num2, sizeof(num2));
		ast_callerid_parse(buf, &name, &num);
		ast_shrink_phone_number(buf);
		break;
	case 6: {
		struct ast_json_error err;
		struct ast_json *json = ast_json_load_buf(buf, len, &err);
		if (json) {
			char *dump = ast_json_dump_string(json);
			ast_json_free(dump);
			ast_json_unref(json);
		}
		break;
	}
	default: {
		struct ast_sockaddr addr;
		struct ast_ha *ha;
		int error = 0;
		char *sep = strchr(buf, '|');
		if (sep) {
			*sep++ = '\0';
		}
		if (ast_sockaddr_parse(&addr, sep ? sep : buf, 0)) {
			ast_sockaddr_stringify(&addr);
		}
		ha = ast_append_ha("permit", buf, NULL, &error);
		if (ha) {
			if (sep && ast_sockaddr_parse(&addr, sep, 0)) {
				ast_apply_ha(ha, &addr);
			}
			ast_free_ha(ha);
		}
		break;
	}
	}
	ast_free(buf);
	return 0;
}
