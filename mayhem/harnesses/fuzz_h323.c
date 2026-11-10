/* H.323 wire decoders in the bundled ooh323c stack (addons/ooh323c, chan_ooh323): Q.931 messages and
 * their H.225 UUIE, H.225 RAS (gatekeeper) PER messages and H.245 control PER messages. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "asterisk.h"
#include <stdint.h>
#include <string.h>
#include "ootypes.h"
#include "ooasn1.h"
#include "ooCalls.h"
#include "ooq931.h"
#include "ooh323ep.h"
#include "ootrace.h"
#include "h323/H323-MESSAGES.h"
#include "h323/MULTIMEDIA-SYSTEM-CONTROL.h"

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

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	/* The stack traces through gH323ep.fptraceFile, which ooH323EpInitialize() would open. */
	gH323ep.fptraceFile = open_discard_stream();
	return 0;
}

/* Input: [selector][message ...]. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	OOCTXT ctxt;
	OOH323CallData call;
	/* Every caller in the stack (oochannels.c) receives into an `ASN1OCTET message[MAXMSGLEN]`
	 * and rejects `len > MAXMSGLEN - 4`; the decoders may read ahead inside that array, so the
	 * message is delivered the same way (zero-filled, so a result depends only on the input). */
	uint8_t buf[MAXMSGLEN];
	size_t len;

	if (size < 2 || size - 1 > MAXMSGLEN - 4) {
		return -1;
	}
	len = size - 1;
	memset(buf, 0, sizeof(buf));
	memcpy(buf, data + 1, len);

	if (initContext(&ctxt) != ASN_OK) {
		return -1;
	}

	switch (data[0] % 3) {
	case 0: {
		Q931Message *msg;
		memset(&call, 0, sizeof(call));
		call.msgctxt = &ctxt;
		call.pctxt = &ctxt;
		strcpy(call.callType, "incoming");
		strcpy(call.callToken, "fuzz");
		msg = memAlloc(&ctxt, sizeof(*msg));
		if (msg) {
			memset(msg, 0, sizeof(*msg));
			if (ooQ931Decode(&call, msg, (int) len, buf, 1) == ASN_OK
				&& msg->messageType == Q931SetupMsg) {
				ooDecodeUUIE(&ctxt, msg);
			}
		}
		break;
	}
	case 1: {
		H225RasMessage ras;
		memset(&ras, 0, sizeof(ras));
		if (setPERBuffer(&ctxt, buf, (ASN1UINT) len, TRUE) == ASN_OK) {
			asn1PD_H225RasMessage(&ctxt, &ras);
		}
		break;
	}
	default: {
		H245MultimediaSystemControlMessage h245;
		memset(&h245, 0, sizeof(h245));
		if (setPERBuffer(&ctxt, buf, (ASN1UINT) len, TRUE) == ASN_OK) {
			asn1PD_H245MultimediaSystemControlMessage(&ctxt, &h245);
		}
		break;
	}
	}
	freeContext(&ctxt);
	return 0;
}
