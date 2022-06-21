#include "myASN.h"

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define REALLOC(x,y) HeapReAlloc(GetProcessHeap(),0,(x),(y))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))


/* add new name and val in struct nameval */
int asn1_add_val(ASN_val asn_add)
{
	ASN_val *nvp;

	if (asn_add.iType == -1) 
	{
		printf("Error -1 not allowed \n");
		return -1;
	}

	if (asn1.asn_val == NULL)
	{
		asn1.asn_val = (ASN_val *)MALLOC(1 * sizeof(ASN_val));
		if (asn1.asn_val == NULL)
		{
			printf("error asn_val init\n");
			return -1;
		}
		asn1.max = 1;
		asn1.nval = 0;
	}
	else if (asn1.nval >= asn1.max)
	{
		nvp = (ASN_val*)REALLOC(asn1.asn_val, (2 * asn1.max) * sizeof(ASN_val));
		if (nvp == NULL) //perviy raz
		{
			printf("error realloc\n");
			return -1;
		}
		asn1.max *= 2;
		asn1.asn_val = nvp;
	}
	else
	{
		//printf("Some unknown error?\n");
	}

	asn1.asn_val[asn1.nval] = asn_add;
	return asn1.nval++;
}

void listAll(void)
{
	printf("call listAll\n<== \n");
	for (int i = 0; i < asn1.nval; i++)
	{
		printf("len %d  type %d data :", asn1.asn_val[i].iLen, asn1.asn_val[i].iType);
		hex_dump(4, 16, 0, asn1.asn_val[i].data, asn1.asn_val[i].iLen);
	}
	printf("==>\n");

}


char * asn1_get_val(unsigned short int asn1_type,UINT16 elemNum)
{
	UINT16 pos = 0;

	for (int i = 0; i < asn1.nval; i++)
	{
		if (asn1.asn_val[i].iType == asn1_type)
		{
			pos++;

			if (pos == elemNum) //сделать указателем на переменную, и возвращать туда длину
			{
				//asn1.asn_val[i].iLen;
				return asn1.asn_val[i].data;
			}
		}
	}

	return NULL;

}

void asn1_free()
{
	for (int i = 0; i < asn1.nval; i++)
	{
		FREE(asn1.asn_val[i].data);
	}
	FREE(asn1.asn_val);
}

void asn1_decode(LPBYTE pbData, DWORD cbData)
{
	LPVOID decoded;
	DWORD sz = 0;
	if (CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_SEQUENCE_OF_ANY, pbData, cbData, CRYPT_DECODE_ALLOC_FLAG, NULL, &decoded, &sz))
	{
		PCRYPT_SEQUENCE_OF_ANY asn = (PCRYPT_SEQUENCE_OF_ANY)decoded;
		PCRYPT_DER_BLOB pa = (PCRYPT_DER_BLOB)asn->rgValue;
		for (UINT i = 0; i < asn->cValue; pa++, i++)
		{
			UINT8 asn_type = pa->pbData[0];
			UINT16 asn_len = pa->pbData[1];
			ASN_val tmp;

			switch (asn_type)
			{
			case 0x30: //SEQUENCE and SEQUENCE OF - recursive search
				DecodeASN(pa->pbData, pa->cbData);
				break;

			case 0x2:
				puts("INT VALUE:");
				goto P;

			case 0x4: //OCTET STRING
				puts("OCTET STRING:");
				goto P;

			case 0x6: //OBJECT IDENTIFIER
				puts("OBJECT:");
				goto P;

			default:
				puts("UNKNOWN VALUE:");
			P:
				tmp.iLen = asn_len;
				tmp.iType = asn_type;
				tmp.data = MALLOC(tmp.iLen);
				memcpy(tmp.data, pa->pbData + 2, asn_len);
				asn1_add_val(tmp);

				printf("LEN : %d \n", asn_len);
				hex_dump(4, 16, 0, pa->pbData + 2, asn_len);
			}


		}

		LocalFree(decoded);
	}
	else
		printf("error decode %d\n", GetLastError());
}
