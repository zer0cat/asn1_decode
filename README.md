# asn1_decode
## ASN.1 decode in pure WinApi

Simple ASN.1 decode in WinApi (no dependencies of 3rd-part libraries). 


### Простой декодер ASN.1 на чистом винапи (без каких-либо зависимостей). Использование

```
data = CreateFile or another..
asn1_decode(data,size_of_data);

ASN_decoded test;
test.len = 1; //position (number first,second) IN, len OUT
test.data = asn1_get_val(asn_type (see header), test.len);
asn1_free();
```
