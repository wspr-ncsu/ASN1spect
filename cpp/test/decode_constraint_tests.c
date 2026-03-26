#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <asn_application.h>
// #include <uper_support.h>
// #include <uper_encoder.h>
// #include <TypeSpecification.h>
#include <FANSSpeedMach.h>

static ssize_t write_out(const void *buffer, size_t size, void *app_key)
{
	fwrite(buffer, 1, size, (FILE *)app_key);
	return size;
}

int main(int argc, char **argv)
{
	FANSSpeedMach_t *t = (FANSSpeedMach_t *)calloc(1, sizeof(FANSSpeedMach_t));

	long test = -12;

	t = &test;

	char buf[256];
	long unsigned int len = sizeof(buf);

	asn_enc_rval_t res = der_encode_to_buffer(&asn_DEF_FANSSpeedMach, t, &buf, sizeof(buf));

	printf("Result: %d\n", res.encoded);
	FANSSpeedMach_t *t2 = (FANSSpeedMach_t *)calloc(1, sizeof(FANSSpeedMach_t));

	asn_dec_rval_t res_dec = ber_decode(0, &asn_DEF_FANSSpeedMach, (void **)t2, buf, sizeof(buf));

	printf("Result: code: %d consumed: %d\n", res_dec.code, res_dec.consumed);

	char errbuf[128];				/* Buffer for error message */
	size_t errlen = sizeof(errbuf); /* Size of the buffer */
	int ret = asn_check_constraints(&asn_DEF_FANSSpeedMach, t2, errbuf, &errlen);

	printf("Result from constraint check: %d %s\n", ret, errbuf);

	return 0;
}
