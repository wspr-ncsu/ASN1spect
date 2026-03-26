#include <stdio.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <errno.h>
#include <asn_application.h>
#include <Color.h>

void constraints_should_prevent_this_ber()
{
	Color_t test = 500; // allowed range is value >= 0, <= 2
	int buf_size = 256;
	uint8_t buf[buf_size];

	asn_enc_rval_t encoding = der_encode_to_buffer(&asn_DEF_Color, &test, (void *)buf, sizeof(buf));

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
		printf("der_encode succeeded, %ld bytes\n", encoding.encoded);
		for (int i = 0; i < encoding.encoded; ++i)
		{
			printf("%02x ", buf[i]);
		}
		printf("(%ld bytes)\n", encoding.encoded);
	}

	Color_t *p = (Color_t *)calloc(1, sizeof(Color_t));

	if (!p)
	{
		perror("calloc failed");
		exit(1);
	}

	memset(p, 0, sizeof(Color_t));

	printf("Before Color_t: %ld\n", *p);

	asn_dec_rval_t retval = ber_decode(0, &asn_DEF_Color, (void **)&p, (const void *)buf, encoding.encoded);

	if(retval.code == RC_OK)
	{
		printf("successfully decoded Color_t: %ld\n", *p);
	}
	else
	{
		printf("ber_decode failed, %d", retval.code);
	}

	// -------------------------------------------------------------------------------------------------------------------------------------------------
}

void constraints_should_prevent_this_per()
{

	Color_t test = 500; // allowed range is value >= 0, <= 2
	int buf_size = 256;
	uint8_t buf[buf_size];

	asn_enc_rval_t encoding = uper_encode_to_buffer(&asn_DEF_Color, 0, &test, (void *)buf, sizeof(buf));

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
		printf("uper_encode succeeded, %ld bytes\n", encoding.encoded);
		for (int i = 0; i < encoding.encoded; ++i)
		{
			printf("%02x ", buf[i]);
		}
		printf("(%ld bytes)\n", encoding.encoded);
	}

	Color_t *p = (Color_t *)calloc(1, sizeof(Color_t));

	if (!p)
	{
		perror("calloc failed");
		exit(1);
	}

	memset(p, 0, sizeof(Color_t));

	printf("Before Color_t: %ld\n", *p);

	asn_dec_rval_t retval = uper_decode(0, &asn_DEF_Color, (void **)&p, (const void *)buf, encoding.encoded, 0, 0);

	if(retval.code == RC_OK)
	{
		printf("Color_t: %ld\n", *p);
	}
	else
	{
		printf("uper_decode failed, %d", retval.code);
	}

	// -------------------------------------------------------------------------------------------------------------------------------------------------

}

int main(int argc, char **argv)
{
	constraints_should_prevent_this_ber();
	constraints_should_prevent_this_per();
	return 0;
}