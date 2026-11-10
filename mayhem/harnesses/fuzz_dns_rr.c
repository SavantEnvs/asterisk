/* DNS resource-record parsers (main/dns_srv.c, dns_naptr.c, dns_txt.c) over a raw DNS answer. */
#include "asterisk.h"
#include <stdint.h>
#include <string.h>
#include <arpa/nameser.h>
#include "asterisk/dns_core.h"
#include "asterisk/dns_internal.h"
#include "asterisk/dns_srv.h"
#include "asterisk/dns_naptr.h"
#include "asterisk/dns_txt.h"

/* Input: [type selector][rdata offset hi][lo][rdata length hi][lo][raw DNS answer ...]
 * The rdata is a slice of the answer, as dns_find_record() requires; the answer is the base
 * for name-compression pointers in dn_expand(). */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct ast_dns_result result = { 0 };
	struct ast_dns_query query = { .result = &result };
	struct ast_dns_record *record = NULL;
	size_t off, len, answer_size;
	char *answer;

	if (size < 6) {
		return -1;
	}
	off = (data[1] << 8) | data[2];
	len = (data[3] << 8) | data[4];
	answer_size = size - 5;
	if (len == 0 || off + len > answer_size) {
		return -1;
	}
	answer = ast_malloc(answer_size);
	memcpy(answer, data + 5, answer_size);
	result.answer = answer;
	result.answer_size = answer_size;

	switch (data[0] % 3) {
	case 0:
		record = dns_srv_alloc(&query, answer + off, len);
		if (record) {
			ast_dns_srv_get_host(record);
			ast_dns_srv_get_priority(record);
			ast_dns_srv_get_weight(record);
			ast_dns_srv_get_port(record);
		}
		break;
	case 1:
		record = dns_naptr_alloc(&query, answer + off, len);
		if (record) {
			ast_dns_naptr_get_flags(record);
			ast_dns_naptr_get_service(record);
			ast_dns_naptr_get_regexp(record);
			ast_dns_naptr_get_replacement(record);
			ast_dns_naptr_get_order(record);
			ast_dns_naptr_get_preference(record);
		}
		break;
	default:
		record = dns_txt_alloc(&query, answer + off, len);
		if (record) {
			struct ast_vector_string *strings = ast_dns_txt_get_strings(record);
			if (strings) {
				ast_dns_txt_free_strings(strings);
			}
		}
		break;
	}
	ast_free(record);
	ast_free(answer);
	return 0;
}
