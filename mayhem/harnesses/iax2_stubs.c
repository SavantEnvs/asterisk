#include "asterisk.h"
#include "iax2/include/parser.h"

/* Defined in chan_iax2.c / provision.c, which are not linked: only used by the frame dump helpers. */
const char *iax2_getformatname(iax2_format format)
{
	return "fuzz";
}

int iax_provflags2str(char *buf, int buflen, unsigned int flags)
{
	return 0;
}
