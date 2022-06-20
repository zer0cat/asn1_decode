#include "myASN.h"

//simple memory wrappers, you can use malloc instead
LPVOID mem_alloc(SIZE_T sz)
{
	return  HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
}

BOOL mem_free(LPVOID m)
{
	return HeapFree(GetProcessHeap(), 0, m);
}

LPVOID mem_realloc(LPVOID m,SIZE_T sz)
{
	return  HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, m, sz);
}

/* add new name and val in dyn array list */
int add_data(ASN_val asn_add)
{
	ASN_val *nvp;

	if (asn1.asn_val == NULL) //perviy raz
	{
		asn1.asn_val = (ASN_val *)mem_alloc(1 * sizeof(ASN_val));
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
		nvp = (ASN_val*)mem_realloc(asn1.asn_val, (2 * asn1.max) * sizeof(ASN_val));
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

/* print all array, for debug propose */
void listAll(void) 
{
	for (int i = 0; i < asn1.nval; i++)
	{
		printf("len %d  type %d data :", asn1.asn_val[i].iLen, asn1.asn_val[i].iType);
		//hex_dump(asn1.asn_val[i].data, asn1.asn_val[i].iLen);
	}
	printf(\n");
}

void asn1_free()
{
	for (int i = 0; i < asn1.nval; i++)
	{
		mem_free(asn1.asn_val[i].data);
	}
	mem_free(asn1.asn_val);
}

void DecodeASN(LPBYTE pbData, DWORD cbData)
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

			switch (asn_type) //http://citforum.ru/nets/semenov/4/44/asn44132.shtml
			{
			case 0x30: //SEQUENCE and SEQUENCE OF - recursive parse data
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
				tmp.data = mem_alloc(tmp.iLen);
				memcpy(tmp.data, pa->pbData + 2, asn_len);
				add_data(tmp);

				printf("LEN : %d \n", asn_len);
				hex_dump(4, 16, 0, pa->pbData + 2, asn_len);
			}


		}

		LocalFree(decoded);
	}
	else
		printf("error decode %d\n", GetLastError());
}
