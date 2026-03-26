enum asn_struct_free_method
{
	ASFM_FREE_EVERYTHING,
	ASFM_FREE_UNDERLYING,
	ASFM_FREE_UNDERLYING_AND_RESET
};

typedef struct asn_codec_ctx_s
{
	/*
	 * Limit the decoder routines to use no (much) more stack than a given
	 * number of bytes. Most of decoders are stack-based, and this
	 * would protect against stack overflows if the number of nested
	 * encodings is high.
	 * The OCTET STRING, BIT STRING and ANY BER decoders are heap-based,
	 * and are safe from this kind of overflow.
	 * A value from getrlimit(RLIMIT_STACK) may be used to initialize
	 * this variable. Be careful in multithreaded environments, as the
	 * stack size is rather limited.
	 */
	size_t max_stack_size; /* 0 disables stack bounds checking */
} asn_codec_ctx_t;

typedef void(asn_struct_free_f)(
	const struct asn_TYPE_descriptor_s *type_descriptor,
	void *struct_ptr, enum asn_struct_free_method);
typedef int(asn_struct_compare_f)(
	const struct asn_TYPE_descriptor_s *type_descriptor,
	const void *struct_A,
	const void *struct_B);

typedef int(asn_app_consume_bytes_f)(const void *buffer, size_t size,
									 void *application_specific_key);

typedef int(asn_struct_print_f)(
	const struct asn_TYPE_descriptor_s *type_descriptor,
	const void *struct_ptr,
	int level, /* Indentation level */
	asn_app_consume_bytes_f *callback, void *app_key);

typedef unsigned ber_tlv_tag_t;

typedef ber_tlv_tag_t(asn_outmost_tag_f)(
	const struct asn_TYPE_descriptor_s *type_descriptor,
	const void *struct_ptr, int tag_mode, ber_tlv_tag_t tag);

enum asn_dec_rval_code_e
{
	RC_OK,	  /* Decoded successfully */
	RC_WMORE, /* More data expected, call again */
	RC_FAIL	  /* Failure to decode data */
};
typedef struct asn_dec_rval_s
{
	enum asn_dec_rval_code_e code; /* Result code */
	size_t consumed;			   /* Number of bytes consumed */
} asn_dec_rval_t;

typedef struct asn_enc_rval_s
{
	/*
	 * Number of bytes encoded.
	 * -1 indicates failure to encode the structure.
	 * In this case, the members below this one are meaningful.
	 */
	ssize_t encoded;

	/*
	 * Members meaningful when (encoded == -1), for post mortem analysis.
	 */

	/* Type which cannot be encoded */
	const struct asn_TYPE_descriptor_s *failed_type;

	/* Pointer to the structure of that type */
	const void *structure_ptr;
} asn_enc_rval_t;

// typedef void(ber_type_decoder_f)(void);
typedef asn_dec_rval_t(ber_type_decoder_f)(
	const struct asn_codec_ctx_s *opt_codec_ctx,
	const struct asn_TYPE_descriptor_s *type_descriptor, void **struct_ptr,
	const void *buf_ptr, size_t size, int tag_mode);

typedef asn_enc_rval_t(der_type_encoder_f)(
	const struct asn_TYPE_descriptor_s *type_descriptor,
	const void *struct_ptr,										  /* Structure to be encoded */
	int tag_mode,												  /* {-1,0,1}: IMPLICIT, no, EXPLICIT */
	ber_tlv_tag_t tag, asn_app_consume_bytes_f *consume_bytes_cb, /* Callback */
	void *app_key												  /* Arbitrary callback argument */
);

enum xer_encoder_flags_e
{
	/* Mode of encoding */
	XER_F_BASIC = 0x01,	   /* BASIC-XER (pretty-printing) */
	XER_F_CANONICAL = 0x02 /* Canonical XER (strict rules) */
};

typedef asn_dec_rval_t(xer_type_decoder_f)(
	const asn_codec_ctx_t *opt_codec_ctx,
	const struct asn_TYPE_descriptor_s *type_descriptor, void **struct_ptr,
	const char *opt_mname, /* Member name */
	const void *buf_ptr, size_t size);

typedef asn_enc_rval_t(xer_type_encoder_f)(
	const struct asn_TYPE_descriptor_s *type_descriptor,
	const void *struct_ptr, /* Structure to be encoded */
	int ilevel,				/* Level of indentation */
	enum xer_encoder_flags_e xer_flags,
	asn_app_consume_bytes_f *consume_bytes_cb, /* Callback */
	void *app_key							   /* Arbitrary callback argument */
);

enum jer_encoder_flags_e
{
	/* Mode of encoding */
	JER_F = 0x01,		   /* JER (pretty-printing) */
	JER_F_MINIFIED = 0x02, /* JER (minified) */
};

typedef asn_dec_rval_t(jer_type_decoder_f)(
	const asn_codec_ctx_t *opt_codec_ctx,
	const struct asn_TYPE_descriptor_s *type_descriptor, void **struct_ptr,
	const void *buf_ptr, size_t size);

typedef asn_enc_rval_t(jer_type_encoder_f)(
	const struct asn_TYPE_descriptor_s *type_descriptor,
	const void *struct_ptr, /* Structure to be encoded */
	int ilevel,				/* Level of indentation */
	enum jer_encoder_flags_e jer_flags,
	asn_app_consume_bytes_f *consume_bytes_cb, /* Callback */
	void *app_key							   /* Arbitrary callback argument */
);

typedef struct asn_per_constraint_s
{
	enum asn_per_constraint_flags
	{
		APC_UNCONSTRAINED = 0x0,
		APC_SEMI_CONSTRAINED = 0x1,
		APC_CONSTRAINED = 0x2,
		APC_EXTENSIBLE = 0x4
	} flags;
	int range_bits;
	int effective_bits;
	long lower_bound;
	long upper_bound;
} asn_per_constraint_t;

typedef struct asn_per_constraints_s
{
	asn_per_constraint_t value;
	asn_per_constraint_t size;
	int (*value2code)(unsigned int value);
	int (*code2value)(unsigned int code);
} asn_per_constraints_t;

typedef struct asn_bit_data_s
{
	const uint8_t *buffer; /* Pointer to the octet stream */
	size_t nboff;		   /* Bit offset to the meaningful bit */
	size_t nbits;		   /* Number of bits in the stream */
	size_t moved;		   /* Number of bits moved through this bit stream */
	int (*refill)(struct asn_bit_data_s *);
	void *refill_key;
} asn_bit_data_t;

typedef struct asn_bit_data_s asn_per_data_t;

typedef struct asn_bit_outp_s
{
	uint8_t *buffer;	  /* Pointer into the (tmpspace) */
	size_t nboff;		  /* Bit offset to the meaningful bit */
	size_t nbits;		  /* Number of bits left in (tmpspace) */
	uint8_t tmpspace[32]; /* Preliminary storage to hold data */
	int (*output)(const void *data, size_t size, void *op_key);
	void *op_key;		  /* Key for (output) data callback */
	size_t flushed_bytes; /* Bytes already flushed through (output) */
} asn_bit_outp_t;

typedef struct asn_bit_outp_s asn_per_outp_t;

typedef asn_dec_rval_t(per_type_decoder_f)(
	const asn_codec_ctx_t *opt_codec_ctx,
	const struct asn_TYPE_descriptor_s *type_descriptor,
	const asn_per_constraints_t *constraints, void **struct_ptr,
	asn_per_data_t *per_data);

typedef asn_enc_rval_t(per_type_encoder_f)(
	const struct asn_TYPE_descriptor_s *type_descriptor,
	const asn_per_constraints_t *constraints, const void *struct_ptr,
	asn_per_outp_t *per_output);

typedef struct asn_oer_constraint_number_s
{
	unsigned width;	   /* ±8,4,2,1 fixed bytes */
	unsigned positive; /* 1 for unsigned number, 0 for signed */
} asn_oer_constraint_number_t;
typedef struct asn_oer_constraints_s
{
	asn_oer_constraint_number_t value;
	ssize_t size; /* -1 (no constraint) or >= 0 */
} asn_oer_constraints_t;

typedef asn_dec_rval_t(oer_type_decoder_f)(
	const struct asn_codec_ctx_s *opt_codec_ctx,
	const struct asn_TYPE_descriptor_s *type_descriptor,
	const asn_oer_constraints_t *constraints,
	void **struct_ptr,
	const void *buf_ptr,
	size_t size);
typedef void(oer_type_encoder_f)(void);

typedef void(asn_random_fill_f)(void);

typedef struct asn_TYPE_operation_s
{
	asn_struct_free_f *free_struct;		  /* Free the structure */
	asn_struct_print_f *print_struct;	  /* Human readable output */
	asn_struct_compare_f *compare_struct; /* Compare two structures */
	ber_type_decoder_f *ber_decoder;	  /* Generic BER decoder */
	der_type_encoder_f *der_encoder;	  /* Canonical DER encoder */
	xer_type_decoder_f *xer_decoder;	  /* Generic XER decoder */
	xer_type_encoder_f *xer_encoder;	  /* [Canonical] XER encoder */
	jer_type_decoder_f *jer_decoder;	  /* Generic JER encoder */
	jer_type_encoder_f *jer_encoder;	  /* Generic JER encoder */
	oer_type_decoder_f *oer_decoder;	  /* Generic OER decoder */
	oer_type_encoder_f *oer_encoder;	  /* Canonical OER encoder */
	per_type_decoder_f *uper_decoder;	  /* Unaligned PER decoder */
	per_type_encoder_f *uper_encoder;	  /* Unaligned PER encoder */
	per_type_decoder_f *aper_decoder;	  /* Aligned PER decoder */
	per_type_encoder_f *aper_encoder;	  /* Aligned PER encoder */
	asn_random_fill_f *random_fill;		  /* Initialize with a random value */
	asn_outmost_tag_f *outmost_tag;		  /* <optional, internal> */
} asn_TYPE_operation_t;

typedef void(asn_app_constraint_failed_f)(void *application_specific_key,
										  const struct asn_TYPE_descriptor_s *type_descriptor_which_failed,
										  const void *structure_which_failed_ptr,
										  const char *error_message_format, ...);

typedef int(asn_constr_check_f)(
	const struct asn_TYPE_descriptor_s *type_descriptor, const void *struct_ptr,
	asn_app_constraint_failed_f *optional_callback,
	void *optional_app_key);

typedef struct asn_encoding_constraints_s
{
	const struct asn_oer_constraints_s *oer_constraints;
	const struct asn_per_constraints_s *per_constraints;
	asn_constr_check_f *general_constraints;
} asn_encoding_constraints_t;

typedef struct asn_encoding_constraints_s_no_oer
{
	const struct asn_per_constraints_s *per_constraints;
	asn_constr_check_f *general_constraints;
} asn_encoding_constraints_t_no_oer;

typedef struct asn_encoding_constraints_s_no_per
{
	const struct asn_oer_constraints_s *oer_constraints;
	asn_constr_check_f *general_constraints;
} asn_encoding_constraints_t_no_per;

typedef struct asn_encoding_constraints_s_neither
{
	asn_constr_check_f *general_constraints;
} asn_encoding_constraints_t_neither;

enum asn_TYPE_flags_e
{
	ATF_NOFLAGS,
	ATF_POINTER = 0x01,
	ATF_OPEN_TYPE = 0x02,
	ATF_ANY_TYPE = 0x04
};

typedef struct asn_type_selector_result_s
{
	const struct asn_TYPE_descriptor_s *type_descriptor; /* Type encoded. */
	unsigned presence_index;							 /* Associated choice variant. */
} asn_type_selector_result_t;

typedef asn_type_selector_result_t(asn_type_selector_f)(
	const struct asn_TYPE_descriptor_s *parent_type_descriptor,
	const void *parent_structure_ptr);

typedef struct asn_TYPE_descriptor_s
{
	const char *name;
	const char *xml_tag;

	asn_TYPE_operation_t *op;

	const ber_tlv_tag_t *tags;
	unsigned tags_count;
	const ber_tlv_tag_t *all_tags;
	unsigned all_tags_count;

	asn_encoding_constraints_t encoding_constraints;

	struct asn_TYPE_member_s *elements;
	unsigned int elements_count;

	const void *specifics;
} asn_TYPE_descriptor_t;

typedef struct asn_TYPE_descriptor_s_no_oer
{
	const char *name;
	const char *xml_tag;

	asn_TYPE_operation_t *op;

	const ber_tlv_tag_t *tags;
	unsigned tags_count;
	const ber_tlv_tag_t *all_tags;
	unsigned all_tags_count;

	asn_encoding_constraints_t_no_oer encoding_constraints;

	struct asn_TYPE_member_s_no_oer *elements;
	unsigned int elements_count;

	const void *specifics;
} asn_TYPE_descriptor_t_no_oer;

typedef struct asn_TYPE_descriptor_s_no_per
{
	const char *name;
	const char *xml_tag;

	asn_TYPE_operation_t *op;

	const ber_tlv_tag_t *tags;
	unsigned tags_count;
	const ber_tlv_tag_t *all_tags;
	unsigned all_tags_count;

	asn_encoding_constraints_t_no_per encoding_constraints;

	struct asn_TYPE_member_s_no_per *elements;
	unsigned int elements_count;

	const void *specifics;
} asn_TYPE_descriptor_t_no_per;

typedef struct asn_TYPE_descriptor_s_neither
{
	const char *name;
	const char *xml_tag;

	asn_TYPE_operation_t *op;

	const ber_tlv_tag_t *tags;
	unsigned tags_count;
	const ber_tlv_tag_t *all_tags;
	unsigned all_tags_count;

	asn_encoding_constraints_t_neither encoding_constraints;

	struct asn_TYPE_member_s_neither *elements;
	unsigned int elements_count;

	const void *specifics;
} asn_TYPE_descriptor_t_neither;

typedef struct asn_TYPE_descriptor_s_legacy
{
	const char *name;
	const char *xml_tag;

	asn_struct_free_f  *free_struct;
	asn_struct_print_f *print_struct;
	asn_constr_check_f *check_constraints;
	ber_type_decoder_f *ber_decoder;
	der_type_encoder_f *der_encoder;
	xer_type_decoder_f *xer_decoder;
	xer_type_encoder_f *xer_encoder;
	per_type_decoder_f *uper_decoder;
	per_type_encoder_f *uper_encoder;

	asn_outmost_tag_f  *outmost_tag;
	const ber_tlv_tag_t *tags;
	int tags_count;
	const ber_tlv_tag_t *all_tags;
	int all_tags_count;

	asn_per_constraints_t *per_constraints;

	struct asn_TYPE_member_s *elements;
	int elements_count;

	const void *specifics;
} asn_TYPE_descriptor_t_legacy;

typedef struct asn_TYPE_descriptor_s_legacy_with_aper
{
	const char *name;
	const char *xml_tag;

	asn_struct_free_f  *free_struct;
	asn_struct_print_f *print_struct;
	asn_constr_check_f *check_constraints;
	ber_type_decoder_f *ber_decoder;
	der_type_encoder_f *der_encoder;
	xer_type_decoder_f *xer_decoder;
	xer_type_encoder_f *xer_encoder;
	per_type_decoder_f *uper_decoder;
	per_type_encoder_f *uper_encoder;
	per_type_decoder_f *aper_decoder;
	per_type_encoder_f *aper_encoder;

	asn_outmost_tag_f  *outmost_tag;
	const ber_tlv_tag_t *tags;
	int tags_count;
	const ber_tlv_tag_t *all_tags;
	int all_tags_count;

	asn_per_constraints_t *per_constraints;

	struct asn_TYPE_member_s *elements;
	int elements_count;

	const void *specifics;
} asn_TYPE_descriptor_t_legacy_with_aper;

typedef struct asn_TYPE_member_s
{
	enum asn_TYPE_flags_e flags;
	unsigned optional;
	unsigned memb_offset;
	ber_tlv_tag_t tag;
	int tag_mode;
	asn_TYPE_descriptor_t *type;
	asn_type_selector_f *type_selector;
	asn_encoding_constraints_t encoding_constraints;
	int (*default_value_cmp)(const void *sptr);
	int (*default_value_set)(void **sptr);
	const char *name;
} asn_TYPE_member_t;

typedef struct asn_TYPE_member_s_no_oer
{
	enum asn_TYPE_flags_e flags;
	unsigned optional;
	unsigned memb_offset;
	ber_tlv_tag_t tag;
	int tag_mode;
	asn_TYPE_descriptor_t_no_oer *type;
	asn_type_selector_f *type_selector;
	asn_encoding_constraints_t_no_oer encoding_constraints;
	int (*default_value_cmp)(const void *sptr);
	int (*default_value_set)(void **sptr);
	const char *name;
} asn_TYPE_member_t_no_oer;

typedef struct asn_TYPE_member_s_no_per
{
	enum asn_TYPE_flags_e flags;
	unsigned optional;
	unsigned memb_offset;
	ber_tlv_tag_t tag;
	int tag_mode;
	asn_TYPE_descriptor_t_no_per *type;
	asn_type_selector_f *type_selector;
	asn_encoding_constraints_t_no_per encoding_constraints;
	int (*default_value_cmp)(const void *sptr);
	int (*default_value_set)(void **sptr);
	const char *name;
} asn_TYPE_member_t_no_per;

typedef struct asn_TYPE_member_s_neither
{
	enum asn_TYPE_flags_e flags;
	unsigned optional;
	unsigned memb_offset;
	ber_tlv_tag_t tag;
	int tag_mode;
	asn_TYPE_descriptor_t_neither *type;
	asn_type_selector_f *type_selector;
	asn_encoding_constraints_t_neither encoding_constraints;
	int (*default_value_cmp)(const void *sptr);
	int (*default_value_set)(void **sptr);
	const char *name;
} asn_TYPE_member_t_neither;

typedef struct asn_TYPE_member_s_legacy
{
	enum asn_TYPE_flags_e flags;
	int optional;
	int memb_offset;
	ber_tlv_tag_t tag;
	int tag_mode;
	asn_TYPE_descriptor_t *type;
	asn_constr_check_f *memb_constraints;
	asn_per_constraints_t *per_constraints;
	int (*default_value)(int setval, void **sptr);
	const char *name;
} asn_TYPE_member_t_legacy;

typedef struct asn_SET_OF_specifics_s
{
	/*
	 * Target structure description.
	 */
	unsigned struct_size; /* Size of the target structure. */
	unsigned ctx_offset;  /* Offset of the asn_struct_ctx_t member */

	/* XER-specific stuff */
	int as_XMLValueList; /* The member type must be encoded like this */
} asn_SET_OF_specifics_t;

enum asn_tag_class
{
	ASN_TAG_CLASS_UNIVERSAL = 0,   /* 0b00 */
	ASN_TAG_CLASS_APPLICATION = 1, /* 0b01 */
	ASN_TAG_CLASS_CONTEXT = 2,	   /* 0b10 */
	ASN_TAG_CLASS_PRIVATE = 3	   /* 0b11 */
};

typedef void(asn_app_constraint_failed_f)(void *application_specific_key,
										  const struct asn_TYPE_descriptor_s *type_descriptor_which_failed,
										  const void *structure_which_failed_ptr,
										  const char *error_message_format, ...);

typedef ssize_t ber_tlv_len_t;

typedef struct asn_struct_ctx_s
{
	short phase;		/* Decoding phase */
	short step;			/* Elementary step of a phase */
	int context;		/* Other context information */
	void *ptr;			/* Decoder-specific stuff (stack elements) */
	ber_tlv_len_t left; /* Number of bytes left, -1 for indefinite */
} asn_struct_ctx_t;

typedef struct BIT_STRING_s
{
	uint8_t *buf; /* BIT STRING body */
	size_t size;  /* Size of the above buffer */

	int bits_unused; /* Unused trailing bits in the last octet (0..7) */

	asn_struct_ctx_t _asn_ctx; /* Parsing across buffer boundaries */
} BIT_STRING_t;

// static int CC_NOTUSED

typedef struct asn_OCTET_STRING_specifics_s
{
	/*
	 * Target structure description.
	 */
	unsigned struct_size; /* Size of the structure */
	unsigned ctx_offset;  /* Offset of the asn_struct_ctx_t member */

	enum asn_OS_Subvariant
	{
		ASN_OSUBV_ANY, /* The open type (ANY) */
		ASN_OSUBV_BIT, /* BIT STRING */
		ASN_OSUBV_STR, /* String types, not {BMP,Universal}String  */
		ASN_OSUBV_U16, /* 16-bit character (BMPString) */
		ASN_OSUBV_U32  /* 32-bit character (UniversalString) */
	} subvariant;
} asn_OCTET_STRING_specifics_t;

static const ber_tlv_tag_t asn_DEF_BIT_STRING_tags[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (3 << 2))};
asn_OCTET_STRING_specifics_t asn_SPC_BIT_STRING_specs = {
	sizeof(BIT_STRING_t),
	offsetof(BIT_STRING_t, _asn_ctx),
	ASN_OSUBV_BIT};
asn_TYPE_operation_t asn_OP_BIT_STRING = {
	OCTET_STRING_free, /* Implemented in terms of OCTET STRING */
#if !defined(ASN_DISABLE_PRINT_SUPPORT)
	BIT_STRING_print,
#else
	0,
#endif /* !defined(ASN_DISABLE_PRINT_SUPPORT) */
	BIT_STRING_compare,
#if !defined(ASN_DISABLE_BER_SUPPORT)
	OCTET_STRING_decode_ber, /* Implemented in terms of OCTET STRING */
	OCTET_STRING_encode_der, /* Implemented in terms of OCTET STRING */
#else
	0,
	0,
#endif /* !defined(ASN_DISABLE_BER_SUPPORT) */
#if !defined(ASN_DISABLE_XER_SUPPORT)
	OCTET_STRING_decode_xer_binary,
	BIT_STRING_encode_xer,
#else
	0,
	0,
#endif /* !defined(ASN_DISABLE_XER_SUPPORT) */
#if !defined(ASN_DISABLE_JER_SUPPORT)
	BIT_STRING_encode_jer,
#else
	0,
#endif /* !defined(ASN_DISABLE_JER_SUPPORT) */
#if !defined(ASN_DISABLE_OER_SUPPORT)
	BIT_STRING_decode_oer,
	BIT_STRING_encode_oer,
#else
	0,
	0,
#endif /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT)
	BIT_STRING_decode_uper, /* Unaligned PER decoder */
	BIT_STRING_encode_uper, /* Unaligned PER encoder */
#else
	0,
	0,
#endif /* !defined(ASN_DISABLE_UPER_SUPPORT) */
#if !defined(ASN_DISABLE_APER_SUPPORT)
	OCTET_STRING_decode_aper, /* Aligned PER decoder */
	OCTET_STRING_encode_aper, /* Aligned PER encoder */
#else
	0,
	0,
#endif /* !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_RFILL_SUPPORT)
	BIT_STRING_random_fill,
#else
	0,
#endif /* !defined(ASN_DISABLE_RFILL_SUPPORT) */
	0  /* Use generic outmost tag fetcher */
};

asn_TYPE_descriptor_t asn_DEF_BIT_STRING = {
	"BIT STRING",
	"BIT_STRING",
	&asn_OP_BIT_STRING,
	asn_DEF_BIT_STRING_tags,
	sizeof(asn_DEF_BIT_STRING_tags) / sizeof(asn_DEF_BIT_STRING_tags[0]),
	asn_DEF_BIT_STRING_tags, /* Same as above */
	sizeof(asn_DEF_BIT_STRING_tags) / sizeof(asn_DEF_BIT_STRING_tags[0]),
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		0,
#endif /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		BIT_STRING_constraint},
	0,
	0, /* No members */
	&asn_SPC_BIT_STRING_specs};

typedef struct asn_TYPE_tag2member_s
{
	ber_tlv_tag_t el_tag; /* Outmost tag of the member */
	unsigned el_no;		  /* Index of the associated member, base 0 */
	int toff_first;		  /* First occurrence of the el_tag, relative */
	int toff_last;		  /* Last occurrence of the el_tag, relative */
} asn_TYPE_tag2member_t;

typedef struct asn_CHOICE_specifics_s
{
	/*
	 * Target structure description.
	 */
	unsigned struct_size; /* Size of the target structure. */
	unsigned ctx_offset;  /* Offset of the asn_codec_ctx_t member */
	unsigned pres_offset; /* Identifier of the present member */
	unsigned pres_size;	  /* Size of the identifier (enum) */

	/*
	 * Tags to members mapping table.
	 */
	const asn_TYPE_tag2member_t *tag2el;
	unsigned tag2el_count;

	/* Canonical ordering of CHOICE elements, for PER */
	const unsigned *to_canonical_order;
	const unsigned *from_canonical_order;

	/*
	 * Extensions-related stuff.
	 */
	signed ext_start; /* First member of extensions, or -1 */
} asn_CHOICE_specifics_t;

typedef struct asn_INTEGER_enum_map_s
{
	long nat_value;		   /* associated native integer value */
	size_t enum_len;	   /* strlen("tag") */
	const char *enum_name; /* "tag" */
} asn_INTEGER_enum_map_t;

typedef struct asn_INTEGER_specifics_s
{
	const asn_INTEGER_enum_map_t *value2enum; /* N -> "tag"; sorted by N */
	const unsigned int *enum2value;			  /* "tag" => N; sorted by tag */
	int map_count;							  /* Elements in either map */
	int extension;							  /* This map is extensible */
	int strict_enumeration;					  /* Enumeration set is fixed */
	int field_width;						  /* Size of native integer */
	int field_unsigned;						  /* Signed=0, unsigned=1 */
} asn_INTEGER_specifics_t;

/*
 * Type of the return value of the encoding functions (der_encode, xer_encode).
 */

typedef struct asn_bit_data_s
{
	const uint8_t *buffer; /* Pointer to the octet stream */
	size_t nboff;		   /* Bit offset to the meaningful bit */
	size_t nbits;		   /* Number of bits in the stream */
	size_t moved;		   /* Number of bits moved through this bit stream */
	int (*refill)(struct asn_bit_data_s *);
	void *refill_key;
} asn_bit_data_t;

typedef struct asn_bit_data_s asn_per_data_t;

typedef struct asn_SEQUENCE_specifics_s
{
	/*
	 * Target structure description.
	 */
	unsigned struct_size; /* Size of the target structure. */
	unsigned ctx_offset;  /* Offset of the asn_struct_ctx_t member */

	/*
	 * Tags to members mapping table (sorted).
	 */
	const asn_TYPE_tag2member_t *tag2el;
	unsigned tag2el_count;

	/*
	 * Optional members of the extensions root (roms) or additions (aoms).
	 * Meaningful for PER.
	 */
	const int *oms;		 /* Optional MemberS */
	unsigned roms_count; /* Root optional members count */
	unsigned aoms_count; /* Additions optional members count */

	/*
	 * Description of an extensions group.
	 * Root components are clustered at the beginning of the structure,
	 * whereas extensions are clustered at the end. -1 means not extensible.
	 */
	signed first_extension; /* First extension addition */
} asn_SEQUENCE_specifics_t;

typedef struct OCTET_STRING
{
	uint8_t *buf; /* Buffer with consecutive OCTET_STRING bits */
	size_t size;  /* Size of the buffer */

	asn_struct_ctx_t _asn_ctx; /* Parsing across buffer boundaries */
} OCTET_STRING_t;

typedef OCTET_STRING_t UTF8String_t; /* Implemented via OCTET STRING */

typedef struct asn_bit_outp_s
{
	uint8_t *buffer;	  /* Pointer into the (tmpspace) */
	size_t nboff;		  /* Bit offset to the meaningful bit */
	size_t nbits;		  /* Number of bits left in (tmpspace) */
	uint8_t tmpspace[32]; /* Preliminary storage to hold data */
	int (*output)(const void *data, size_t size, void *op_key);
	void *op_key;		  /* Key for (output) data callback */
	size_t flushed_bytes; /* Bytes already flushed through (output) */
} asn_bit_outp_t;

typedef struct asn_bit_outp_s asn_per_outp_t;

#define ASN_PRI_SIZE "lu"
#define ASN_PRI_SSIZE "ld"

enum asn_struct_free_method
{
	ASFM_FREE_EVERYTHING,		   /* free(struct_ptr) and underlying members */
	ASFM_FREE_UNDERLYING,		   /* free underlying members */
	ASFM_FREE_UNDERLYING_AND_RESET /* FREE_UNDERLYING + memset(0) */
};
typedef void(asn_struct_free_f)(
	const struct asn_TYPE_descriptor_s *type_descriptor,
	void *struct_ptr, enum asn_struct_free_method);

typedef struct ASN__PRIMITIVE_TYPE_s
{
	uint8_t *buf;		 /* Buffer with consecutive primitive encoding bytes */
	size_t size;		 /* Size of the buffer */
} ASN__PRIMITIVE_TYPE_t; /* Do not use this type directly! */

typedef struct asn_random_fill_result_s
{
	enum
	{
		ARFILL_FAILED = -1, /* System error (memory?) */
		ARFILL_OK = 0,		/* Initialization succeeded */
		ARFILL_SKIPPED = 1	/* Not done due to (length?) constraint */
	} code;
	size_t length; /* Approximate number of bytes created. */
} asn_random_fill_result_t;

typedef asn_random_fill_result_t(asn_random_fill_f)(
	const struct asn_TYPE_descriptor_s *td, void **struct_ptr,
	const struct asn_encoding_constraints_s *memb_constraints,
	size_t max_length);

asn_random_fill_f NULL_random_fill;

typedef int NULL_t;

typedef struct asn_ioc_set_s
{
	size_t rows_count;
	size_t columns_count;
	const struct asn_ioc_cell_s *rows;
} asn_ioc_set_t;

typedef struct asn_ioc_cell_s
{
	const char *field_name; /* Is equal to corresponding column_name */
	enum
	{
		aioc__undefined = 0,
		aioc__value,
		aioc__type,
		aioc__open_type,
	} cell_kind;
	struct asn_TYPE_descriptor_s *type_descriptor;
	const void *value_sptr;
	struct
	{
		size_t types_count;
		struct
		{
			unsigned choice_position;
		} *types;
	} open_type;
} asn_ioc_cell_t;

typedef OCTET_STRING_t PrintableString_t; /* Implemented via OCTET STRING */

typedef ASN__PRIMITIVE_TYPE_t INTEGER_t;

// #include <cstdint>
/* Largest integral types.  */
typedef long int __intmax_t;
typedef unsigned long int __uintmax_t;
typedef long int __intmax_t;
typedef unsigned long int __uintmax_t;
typedef __uintmax_t uintmax_t;
typedef __intmax_t intmax_t;
typedef unsigned char __uint8_t;
typedef __uint8_t uint8_t;

#define A_SET_OF(type)                   \
	struct                               \
	{                                    \
		type **array;                    \
		int count; /* Meaningful size */ \
		int size;  /* Allocated size */  \
		void (*free)(type *);            \
	}

typedef A_SET_OF(void) asn_anonymous_set_;

typedef ASN__PRIMITIVE_TYPE_t OBJECT_IDENTIFIER_t;
typedef uint32_t asn_oid_arc_t;
#define ASN_OID_ARC_MAX (~((asn_oid_arc_t)0))

typedef struct ANY
{
	uint8_t *buf; /* BER-encoded ANY contents */
	int size;	  /* Size of the above buffer */

	asn_struct_ctx_t _asn_ctx; /* Parsing across buffer boundaries */
} ANY_t;

#define A_SEQUENCE_OF(type) A_SET_OF(type)

typedef A_SEQUENCE_OF(void) asn_sequence;

typedef OCTET_STRING_t VisibleString_t; /* Implemented via OCTET STRING */

typedef A_SEQUENCE_OF(void) asn_anonymous_sequence_;
#define _A_SEQUENCE_FROM_VOID(ptr) ((asn_anonymous_sequence_ *)(ptr))
#define _A_CSEQUENCE_FROM_VOID(ptr) ((const asn_anonymous_sequence_ *)(ptr))

#define A_SEQUENCE_OF(type) A_SET_OF(type)

#define ASN_SEQUENCE_ADD(headptr, ptr) \
	asn_sequence_add((headptr), (ptr))

/***********************************************
 * Implementation of the SEQUENCE OF structure.
 */

#define asn_sequence_add asn_set_add
#define asn_sequence_empty asn_set_empty

// From /usr/include/<...>/bits/types/FILE.h
struct _IO_FILE;

/* The opaque type of streams.  This is the definition used elsewhere.  */
typedef struct _IO_FILE FILE;

#define CC_ATTRIBUTE(attr) __attribute__((attr))
#define CC_PRINTFLIKE(fmt, var) CC_ATTRIBUTE(format(printf, fmt, var))

typedef struct enc_dyn_arg
{
	void *buffer;
	size_t length;
	size_t allocated;
} enc_dyn_arg;

#define PRIu32 "u"

typedef struct asn_encode_to_new_buffer_result_s
{
	void *buffer; /* NULL if failed to encode. */
	asn_enc_rval_t result;
} asn_encode_to_new_buffer_result_t;

#define ASN_PRIuMAX "lu"
#define ASN_PRIdMAX "ld"
