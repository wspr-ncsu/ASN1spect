#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <asn_application.h>
// #include <uper_support.h>
// #include <uper_encoder.h>
#include <TypeSpecification.h>

static ssize_t write_out(const void *buffer, size_t size, void *app_key)
{
	fwrite(buffer, 1, size, (FILE *)app_key);
	return size;
}

void encode_infinite_loop()
{
	TypeSpecification_t *type_spec = (TypeSpecification_t *)calloc(1, sizeof(TypeSpecification_t));
	type_spec->present = TypeSpecification_PR_array;
	type_spec->choice.array = (TypeSpecification::TypeSpecification_u::TypeSpecification__array *)calloc(1, sizeof(TypeSpecification::TypeSpecification_u::TypeSpecification__array));
	type_spec->choice.array->numberOfElements = 1;
	type_spec->choice.array->elementType = (TypeSpecification_t *)calloc(1, sizeof(TypeSpecification_t));
	type_spec->choice.array->elementType->present = TypeSpecification_PR_array;

	// Comment this line and uncomment the next to fix infinite loop
	type_spec->choice.array->elementType->choice.array = type_spec->choice.array; // Set the elementType to point to the same TypeSpecification__array_t instance
	//type_spec->choice.array->elementType->choice.array = (TypeSpecification::TypeSpecification_u::TypeSpecification__array *)calloc(1, sizeof(TypeSpecification::TypeSpecification_u::TypeSpecification__array));

	uint8_t buf[256];

	asn_enc_rval_t retval = der_encode(&asn_DEF_TypeSpecification, type_spec, (asn_app_consume_bytes_f *)write_out, (void *)stdout);

	printf("Will never get here\n");
}

// void decode_infinite_loop()
// {
// 	uint8_t bytes[] = {
// 		0x77, 0xFF, 0x40, 0x80, 0x00, 0x00, 0x80, 0xFF, 0x40, 0x80, 0x00, 0x00, 0x80, 0xFF,
// 	};
// 	size_t len = sizeof(bytes) / sizeof(bytes[0]);

// 	asn_dec_rval_t rval;
// 	TypeSpecification_t *type_spec = NULL;

// 	rval = uper_decode(NULL, &asn_DEF_TypeSpecification, (void **)&type_spec, bytes, len, 0, 0);

// 	if(rval.code != RC_OK)
// 	{
// 		printf("Failed to decode!\n");
// 	} else {
// 		printf("Decoded!\n");
// 	}
// }

int main(int argc, char **argv)
{
	encode_infinite_loop();
	//decode_infinite_loop();

	return 0;
}
