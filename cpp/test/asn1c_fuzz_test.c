#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <asn_application.h>
#include <ENBname.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
	ENBname_t *p = NULL;
	asn_dec_rval_t retval = ber_decode(0, &asn_DEF_ENBname, (void **)&p, buf, len);

	if(retval.code == RC_OK) {
		// Provide positive feedback to the fuzzer when decoding succeeds
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_ENBname, p);
		return 1; // Signal success to the fuzzer
	} else {
		// Different return values for different failure scenarios
		return (retval.consumed > 0) ? 2 : 0;
	}
}

int main() {
	return 0;
}