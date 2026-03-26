include Makefile.am.libasncodec

LIBS += -lm
CFLAGS += $(ASN_MODULE_CFLAGS) -DASN_DISABLE_BER_SUPPORT -DASN_DISABLE_XER_SUPPORT -DASN_DISABLE_OER_SUPPORT -DASN_DISABLE_APER_SUPPORT -DASN_PDU_COLLECTION -I.
ASN_LIBRARY ?= libasncodec.a
ASN_PROGRAM ?= converter-example
ASN_PROGRAM_SRCS ?= \
	converter-example.c\
	pdu_collection.c

all: $(ASN_PROGRAM)

$(ASN_PROGRAM): $(ASN_LIBRARY) $(ASN_PROGRAM_SRCS:.c=.o)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $(ASN_PROGRAM) $(ASN_PROGRAM_SRCS:.c=.o) $(LDFLAGS) $(ASN_LIBRARY) $(LIBS)

$(ASN_LIBRARY): $(ASN_MODULE_SRCS:.c=.o)
	$(AR) rcs $@ $(ASN_MODULE_SRCS:.c=.o)

.SUFFIXES:
.SUFFIXES: .c .o

.c.o:
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f $(ASN_PROGRAM) $(ASN_LIBRARY)
	rm -f $(ASN_MODULE_SRCS:.c=.o) $(ASN_PROGRAM_SRCS:.c=.o)

regen: regenerate-from-asn1-source

regenerate-from-asn1-source:
	asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -S /home/swthorn/git/asn1c/skeletons -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-APER -no-gen-JER /home/swthorn/git/playground/asn_paper/asn1/generated/asn1c/38414-h30_backup.asn

