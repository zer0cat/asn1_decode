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

struct ASN1
{
	int nval;
	int max;
	ASN_val *asn_val;
} asn1;

int add_data(ASN_val asn_add);
void listAll(void);
