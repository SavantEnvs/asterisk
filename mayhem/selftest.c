/* Known-answer checks for the same in-process code paths the fuzz harnesses drive, built with the
 * project's normal flags. Each check is a fixed input -> asserted output; mayhem/test.sh requires
 * the exact pass count. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "asterisk.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include "asterisk/ast_expr.h"
#include "asterisk/stun.h"
#include "asterisk/dns_core.h"
#include "asterisk/dns_internal.h"
#include "asterisk/dns_srv.h"
#include "asterisk/dns_naptr.h"
#include "asterisk/config.h"
#include "asterisk/utils.h"
#include "asterisk/strings.h"
#include "asterisk/app.h"
#include "asterisk/callerid.h"
#include "asterisk/json.h"
#include "asterisk/netsock2.h"
#include "asterisk/acl.h"
#include "iax2/include/parser.h"
#include "ootypes.h"
#include "ooasn1.h"
#include "ooCalls.h"
#include "ooq931.h"
#include "ooh323ep.h"

extern ooEndPoint gH323ep;

static ssize_t discard_write(void *cookie, const char *buf, size_t n)
{
	return (ssize_t) n;
}

/* A stream that drops everything written to it, for the stack's trace file. */
static FILE *open_discard_stream(void)
{
	cookie_io_functions_t fns = { .write = discard_write };
	return fopencookie(NULL, "w", fns);
}

static int passed, failed;

#define CHECK(name, cond) do { \
	if (cond) { passed++; printf("PASS: %s\n", name); } \
	else { failed++; printf("FAIL: %s (%s:%d)\n", name, __FILE__, __LINE__); } \
} while (0)

#define EXPR(name, input, want) do { \
	char out[256] = ""; \
	ast_expr((char *) input, out, sizeof(out), NULL); \
	if (strcmp(out, want)) printf("# got [%s]\n", out); \
	CHECK(name, !strcmp(out, want)); \
} while (0)

static int count_attrs(struct stun_attr *attr, void *arg)
{
	/* struct stun_attr is private to main/stun.c: {u16 attr; u16 len; value[]} */
	const uint16_t *hdr = (const uint16_t *) attr;
	if (ntohs(hdr[0]) == 0x0006 && ntohs(hdr[1]) == 32) {
		(*(int *) arg)++;
	}
	return 0;
}

static void test_expr(void)
{
	EXPR("expr add", "1 + 2", "3");
	EXPR("expr precedence", "2 * (3 + 4) - 1", "13");
	EXPR("expr modulo", "17 % 5", "2");
	EXPR("expr string equality", "\"abc\" = \"abc\"", "1");
	EXPR("expr logical and", "10 > 5 & 3 < 4", "1");
	EXPR("expr regex length", "\"hello\" : \"h.*o\"", "5");
	EXPR("expr conditional", "0 ? 7 :: 8", "8");
}

static void test_stun(void)
{
	unsigned char pkt[20 + 4 + 32 + 8] = { 0 };
	struct sockaddr_in src = { .sin_family = AF_INET };
	int seen = 0;
	int res;

	pkt[1] = 0x01;                 /* binding request */
	pkt[3] = 4 + 32;               /* message length */
	memset(pkt + 4, 0xab, 16);     /* transaction id */
	pkt[21] = 0x06;                /* USERNAME */
	pkt[23] = 32;
	memcpy(pkt + 24, "0123456789abcdefFEDCBA9876543210", 32);
	res = ast_stun_handle_packet(-1, &src, pkt, 20 + 4 + 32, count_attrs, &seen);
	CHECK("stun binding request accepted", res == AST_STUN_ACCEPT);
	CHECK("stun username attribute delivered", seen == 1);

	memset(pkt, 0, sizeof(pkt));
	CHECK("stun runt packet rejected", ast_stun_handle_packet(-1, &src, pkt, 7, NULL, NULL) == -1);
}

static void test_dns(void)
{
	static const char srv_rdata[] = {
		0, 10, 0, 20, 0x13, 0xc4,
		3, 's', 'i', 'p', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0
	};
	static const char naptr_rdata[] = {
		0, 100, 0, 10,
		1, 's',
		7, 'S', 'I', 'P', '+', 'D', '2', 'U',
		0,
		4, '_', 's', 'i', 'p', 4, '_', 'u', 'd', 'p', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0
	};
	struct ast_dns_result result = { 0 };
	struct ast_dns_query query = { .result = &result };
	struct ast_dns_record *rec;

	result.answer = (char *) srv_rdata;
	result.answer_size = sizeof(srv_rdata);
	rec = dns_srv_alloc(&query, srv_rdata, sizeof(srv_rdata));
	CHECK("dns srv parsed", rec != NULL);
	if (rec) {
		CHECK("dns srv priority", ast_dns_srv_get_priority(rec) == 10);
		CHECK("dns srv weight", ast_dns_srv_get_weight(rec) == 20);
		CHECK("dns srv port", ast_dns_srv_get_port(rec) == 5060);
		CHECK("dns srv host", !strcmp(ast_dns_srv_get_host(rec), "sip.example.com"));
		ast_free(rec);
	}

	result.answer = (char *) naptr_rdata;
	result.answer_size = sizeof(naptr_rdata);
	rec = dns_naptr_alloc(&query, naptr_rdata, sizeof(naptr_rdata));
	CHECK("dns naptr parsed", rec != NULL);
	if (rec) {
		CHECK("dns naptr order", ast_dns_naptr_get_order(rec) == 100);
		CHECK("dns naptr flags", !strcmp(ast_dns_naptr_get_flags(rec), "s"));
		CHECK("dns naptr service", !strcmp(ast_dns_naptr_get_service(rec), "SIP+D2U"));
		CHECK("dns naptr replacement", !strcmp(ast_dns_naptr_get_replacement(rec), "_sip._udp.example.com"));
		ast_free(rec);
	}
}

static void test_config(void)
{
	static const char text[] =
		"[general]\n"
		"foo=bar\n"
		"baz => qux\n"
		"; a comment\n"
		"[second]\n"
		"key=val ; trailing comment\n";
	struct ast_flags flags = { CONFIG_FLAG_NOCACHE | CONFIG_FLAG_NOREALTIME };
	const char *tmpdir = getenv("TMPDIR");
	char path[256];
	struct ast_config *cfg;
	int fd;

	snprintf(path, sizeof(path), "%s/selftest.XXXXXX", tmpdir && *tmpdir ? tmpdir : "/tmp");
	fd = mkstemp(path);
	CHECK("config temp file", fd >= 0);
	if (fd < 0) {
		return;
	}
	CHECK("config write", write(fd, text, sizeof(text) - 1) == (ssize_t) (sizeof(text) - 1));
	close(fd);
	cfg = ast_config_load2(path, "selftest", flags);
	unlink(path);
	CHECK("config loaded", cfg && cfg != CONFIG_STATUS_FILEMISSING && cfg != CONFIG_STATUS_FILEINVALID);
	if (cfg && cfg != CONFIG_STATUS_FILEMISSING && cfg != CONFIG_STATUS_FILEINVALID) {
		const char *v;
		v = ast_variable_retrieve(cfg, "general", "foo");
		CHECK("config plain variable", v && !strcmp(v, "bar"));
		v = ast_variable_retrieve(cfg, "general", "baz");
		CHECK("config => variable", v && !strcmp(v, "qux"));
		v = ast_variable_retrieve(cfg, "second", "key");
		CHECK("config trailing comment stripped", v && !strcmp(v, "val"));
		ast_config_destroy(cfg);
	}
}

static void test_text(void)
{
	char buf[256], out[256];
	char *s, *tok, *argv[8], *name, *num;
	struct ast_flags http = { 0 };
	struct ast_flags alnum = { AST_URI_ALPHANUM };
	unsigned char dec[64];
	int n;

	strcpy(buf, "%41%20b%2fc");
	ast_uri_decode(buf, http);
	CHECK("uri decode", !strcmp(buf, "A b/c"));

	ast_uri_encode("a b&c", out, sizeof(out), alnum);
	CHECK("uri encode", !strcmp(out, "a%20b%26c"));

	n = ast_base64decode(dec, "TWFuIGlz", sizeof(dec));
	CHECK("base64 decode", n == 6 && !memcmp(dec, "Man is", 6));
	ast_base64encode(out, (const unsigned char *) "Man is", 6, sizeof(out));
	CHECK("base64 encode", !strcmp(out, "TWFuIGlz"));

	strcpy(buf, "a\\tb\\\\c\\q");
	ast_unescape_c(buf);
	CHECK("c unescape", !strcmp(buf, "a\tb\\cq"));

	strcpy(buf, " a , \"b c\" ,d");
	s = buf;
	n = 0;
	out[0] = '\0';
	while ((tok = ast_strsep(&s, ',', AST_STRSEP_ALL))) {
		strcat(out, tok);
		strcat(out, "|");
		n++;
	}
	CHECK("strsep", n == 3 && !strcmp(out, "a|b c|d|"));

	strcpy(buf, "x,y\\,z,w");
	n = __ast_app_separate_args(buf, ',', 1, argv, 8);
	CHECK("separate_args count", n == 3);
	CHECK("separate_args escaped delimiter", n == 3 && !strcmp(argv[1], "y,z"));

	strcpy(buf, "\"Bob Smith\" <5551234>");
	ast_callerid_parse(buf, &name, &num);
	CHECK("callerid name", name && !strcmp(name, "Bob Smith"));
	CHECK("callerid number", num && !strcmp(num, "5551234"));

	strcpy(buf, "(555) 123-4567");
	ast_shrink_phone_number(buf);
	CHECK("phone number shrink", !strcmp(buf, "5551234567"));
}

static void test_json(void)
{
	static const char doc[] = "{\"a\":[1,2,{\"b\":null}],\"c\":\"d\"}";
	struct ast_json_error err;
	struct ast_json *json = ast_json_load_buf(doc, strlen(doc), &err);
	CHECK("json loaded", json != NULL);
	if (json) {
		char *dump = ast_json_dump_string(json);
		CHECK("json round trip", dump && !strcmp(dump, doc));
		CHECK("json string member", !strcmp(ast_json_string_get(ast_json_object_get(json, "c")), "d"));
		ast_json_free(dump);
		ast_json_unref(json);
	}
	CHECK("json garbage rejected", ast_json_load_buf("{\"a\":", 5, &err) == NULL);
}

static void test_net(void)
{
	struct ast_sockaddr addr;
	struct ast_ha *ha;
	int error = 0;

	CHECK("sockaddr v4 parsed", ast_sockaddr_parse(&addr, "192.0.2.1:5060", 0));
	CHECK("sockaddr v4 port", ast_sockaddr_port(&addr) == 5060);
	CHECK("sockaddr v4 string", !strcmp(ast_sockaddr_stringify(&addr), "192.0.2.1:5060"));
	CHECK("sockaddr v6 parsed", ast_sockaddr_parse(&addr, "[2001:db8::1]:5061", 0));
	CHECK("sockaddr v6 port", ast_sockaddr_port(&addr) == 5061);
	CHECK("sockaddr garbage rejected", !ast_sockaddr_parse(&addr, "not an address", 0));

	ha = ast_append_ha("deny", "0.0.0.0/0", NULL, &error);
	ha = ast_append_ha("permit", "10.0.0.0/8", ha, &error);
	CHECK("acl built", ha != NULL && !error);
	ast_sockaddr_parse(&addr, "10.1.2.3", 0);
	CHECK("acl permits 10/8", ast_apply_ha(ha, &addr) == AST_SENSE_ALLOW);
	ast_sockaddr_parse(&addr, "192.168.1.1", 0);
	CHECK("acl denies the rest", ast_apply_ha(ha, &addr) == AST_SENSE_DENY);
	ast_free_ha(ha);
}

static void test_iax2(void)
{
	/* CALLINGTNS (u16 0x0102), then USERNAME "alice" last so the NUL slack terminates it */
	unsigned char ies_buf[] = {
		IAX_IE_CALLINGTNS, 2, 0x01, 0x02,
		IAX_IE_USERNAME, 5, 'a', 'l', 'i', 'c', 'e', 0
	};
	struct iax_ies ies;

	CHECK("iax2 ies parsed", iax_parse_ies(&ies, ies_buf, sizeof(ies_buf) - 1) == 0);
	CHECK("iax2 calling tns", ies.calling_tns == 0x0102);
	CHECK("iax2 username", ies.username && !strcmp(ies.username, "alice"));
	CHECK("iax2 overlong ie rejected", iax_parse_ies(&ies, (unsigned char *) "\x06\x20xx", 4) == -1);
}

static void test_q931(void)
{
	/* Status message (the decoder requires a UUIE for every other type) */
	static const uint8_t status_msg[] = {
		0x08, 0x02, 0x00, 0x2a,
		0x7d,
		0x08, 0x02, 0x80, 0x90
	};
	OOCTXT ctxt;
	OOH323CallData call;
	Q931Message *msg;
	int rc;

	CHECK("h323 context", initContext(&ctxt) == ASN_OK);
	memset(&call, 0, sizeof(call));
	call.msgctxt = &ctxt;
	strcpy(call.callType, "incoming");
	strcpy(call.callToken, "selftest");
	msg = memAlloc(&ctxt, sizeof(*msg));
	memset(msg, 0, sizeof(*msg));
	rc = ooQ931Decode(&call, msg, sizeof(status_msg), (ASN1OCTET *) status_msg, 0);
	CHECK("q931 status decoded", rc == ASN_OK);
	CHECK("q931 message type", msg->messageType == Q931StatusMsg);
	CHECK("q931 call reference", msg->callReference == 42);
	CHECK("q931 cause ie", msg->causeIE && msg->causeIE->length == 2 && msg->causeIE->data[1] == 0x90);
	CHECK("q931 runt rejected", ooQ931Decode(&call, msg, 3, (ASN1OCTET *) status_msg, 0) != ASN_OK);
	freeContext(&ctxt);
}

int main(void)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	/* the H.323 stack traces through this file */
	gH323ep.fptraceFile = open_discard_stream();
	ast_utils_init();
	test_expr();
	test_stun();
	test_dns();
	test_config();
	test_text();
	test_json();
	test_net();
	test_iax2();
	test_q931();
	printf("SELFTEST passed=%d failed=%d\n", passed, failed);
	return failed ? 1 : 0;
}
