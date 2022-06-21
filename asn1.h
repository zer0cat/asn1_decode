#pragma once
#include <stdio.h>
#include <string.h>
#include <windows.h>

enum {INTEGER = 0x2, OCTETSTRING = 0x4, OBJECT_ID = 0x6, SEQUENCE_OF = 0x30};

typedef struct ASN_val ASN_val;

struct ASN_val
{
	unsigned short int iType;
	unsigned short int iLen;
	char *data;
};


typedef struct ASN_decoded ASN_decoded;
struct ASN_decoded
{
	unsigned char *data;
	unsigned short int len;
};

struct ASN1
{
	int nval;
	int max;
	ASN_val *asn_val;
} asn1;

void asn1_decode(LPBYTE pbData, DWORD cbData);
int asn1_add_val(ASN_val asn_add);
char * asn1_get_val(unsigned short int asn1_type, UINT16 *elemNum);
void asn1_free(void);
