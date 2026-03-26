#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <asn_application.h>
#include <Vehicle.h>
#include <FANSDirection.h>

void constraints_should_prevent_this_ber()
{
	FANSDirection_t test = -1;
	uint8_t buf[256];

	asn_enc_rval_t encoding = der_encode_to_buffer(&asn_DEF_FANSDirection, &test, (void *)buf, sizeof(buf));

	if (encoding.encoded == -1)
	{
		fprintf(stderr, "der_encode failed: %s: %s\n", encoding.failed_type->name, strerror(errno));
		// exit(1);
	}
	else if (encoding.encoded > sizeof(buf))
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

	FANSDirection_t *p = (FANSDirection_t *)calloc(1, sizeof(FANSDirection_t));

	if (!p)
	{
		perror("calloc failed");
		exit(1);
	}

	memset(p, 0, sizeof(FANSDirection_t));

	printf("123 Before Color_t: %ld\n", *p);

	asn_dec_rval_t retval = ber_decode(0, &asn_DEF_FANSDirection, (void **)&p, (const void *)buf, encoding.encoded);

	if(retval.code == RC_OK)
	{
		int CompassSymbols[] = {"N", "S", "E", "W"};
		printf("Value: %d\n", colorValues[*p2]);
	}
	else
	{
		printf("ber_decode failed, %d", retval.code);
	}

	// -------------------------------------------------------------------------------------------------------------------------------------------------

	Vehicle_t test2 = 500; // allowed range is value >= 0, <= 2
	int buf_size2 = 256;
	uint8_t buf2[buf_size];

	asn_enc_rval_t encoding2 = der_encode_to_buffer(&asn_DEF_Vehicle, &test2, (void *)buf2, sizeof(buf2));

	if (encoding2.encoded == -1)
	{
		fprintf(stderr, "der_encode failed: %s: %s\n", encoding2.failed_type->name, strerror(errno));
		// exit(1);
	}
	else if (encoding2.encoded > buf_size2)
	{
		perror("encode failed: buffer too small\n");
		// exit(2);
	}
	else
	{
		printf("der_encode succeeded, %ld bytes\n", encoding2.encoded);
		for (int i = 0; i < encoding2.encoded; ++i)
		{
			printf("%02x ", buf2[i]);
		}
		printf("(%ld bytes)\n", encoding2.encoded);
	}

	Vehicle_t *p2 = (Vehicle_t *)calloc(1, sizeof(Vehicle_t));

	if (!p2)
	{
		perror("calloc failed");
		exit(1);
	}

	memset(p2, 0, sizeof(Vehicle_t));

	printf("123 Before Vehicle_t: %ld\n", *p2);

	asn_dec_rval_t retval2 = ber_decode(0, &asn_DEF_Vehicle, (void **)&p2, (const void *)buf2, encoding2.encoded);

	if(retval2.code == RC_OK)
	{
		printf("Vehicle_t: %ld\n", *p2);
	}
	else
	{
		printf("ber_decode failed, %d", retval2.code);
	}

	// -------------------------------------------------

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

	printf("123 Before Color_t: %ld\n", *p);

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

	Vehicle_t test2 = 500; // allowed range is value >= 0, <= 2
	int buf_size2 = 256;
	uint8_t buf2[buf_size];

	asn_enc_rval_t encoding2 = uper_encode_to_buffer(&asn_DEF_Vehicle, 0, &test2, (void *)buf2, sizeof(buf2));

	if (encoding2.encoded == -1)
	{
		fprintf(stderr, "uper_encode_to_buffer failed: %s: %s\n", encoding2.failed_type->name, strerror(errno));
		// exit(1);
	}
	else if (encoding2.encoded > buf_size2)
	{
		perror("encode failed: buffer too small\n");
		// exit(2);
	}
	else
	{
		printf("uper_encode_to_buffer succeeded, %ld bytes\n", encoding2.encoded);
		for (int i = 0; i < encoding2.encoded; ++i)
		{
			printf("%02x ", buf2[i]);
		}
		printf("(%ld bytes)\n", encoding2.encoded);
	}

	Vehicle_t *p2 = (Vehicle_t *)calloc(1, sizeof(Vehicle_t));

	if (!p2)
	{
		perror("calloc failed");
		exit(1);
	}

	memset(p2, 0, sizeof(Vehicle_t));

	printf("123 Before Vehicle_t: %ld\n", *p2);

	asn_dec_rval_t retval2 = uper_decode(0, &asn_DEF_Vehicle, (void **)&p2, (const void *)buf2, encoding2.encoded, 0, 0);

	if(retval2.code == RC_OK)
	{
		printf("Vehicle_t: %ld\n", *p2);
	}
	else
	{
		printf("uper_decode failed, %d", retval2.code);
	}

	// -------------------------------------------------

}

int main(int argc, char **argv)
{
	constraints_should_prevent_this_ber();
	constraints_should_prevent_this_per();
	return 0;
}