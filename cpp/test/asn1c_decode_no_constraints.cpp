#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <asn_application.h>
#include <FANSSpeedIndicatedMetric.h>

void constraints_should_prevent_this()
{
	FANSSpeedIndicatedMetric_t type_spec = 5000; // allowed range is value >= 10 && value <= 137
	int buf_size = 256;
	uint8_t buf[buf_size];

	asn_enc_rval_t encoding = der_encode_to_buffer(&asn_DEF_FANSSpeedIndicatedMetric, &type_spec, (void *)buf, sizeof(buf));

	if (encoding.encoded == -1)
	{
		fprintf(stderr, "der_encode failed: %s: %s\n", encoding.failed_type->name, strerror(errno));
		// exit(1);
	}
	else if (encoding.encoded > buf_size)
	{
		perror("encode failed: buffer too small\n");
		// exit(2);
	}
	else
	{
		printf("der_encode succeeded, %d bytes\n", encoding.encoded);
		for (int i = 0; i < encoding.encoded; ++i)
		{
			printf("%02x ", buf[i]);
		}
		printf("(%d bytes)\n", encoding.encoded);
	}

	FANSSpeedIndicatedMetric_t *p = (FANSSpeedIndicatedMetric_t *)calloc(1, sizeof(FANSSpeedIndicatedMetric_t));

	if (!p)
	{
		perror("calloc failed");
		exit(1);
	}

	memset(p, 0, sizeof(FANSSpeedIndicatedMetric_t));

	printf("123 Before FANSSpeedIndicatedMetric_t: %ld\n", *p);

	asn_dec_rval_t retval = ber_decode(0, &asn_DEF_FANSSpeedIndicatedMetric, (void **)&p, (const void *)buf, encoding.encoded);

	if(retval.code == RC_OK)
	{
		printf("FANSSpeedIndicatedMetric_t: %ld\n", *p);
	}
	else
	{
		printf("ber_decode failed, %d", retval.code);
	}
}

int main(int argc, char **argv)
{
	constraints_should_prevent_this();
	return 0;
}