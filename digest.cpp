#include "sha256.h"


void Digest::reset()
{
	memset(&data[0], 0, sizeof(data)); txtlen = 0; msgsize = 0;
}


void Digest::update(const uint8_t *msg, uint8_t len)
{
	uint8_t *b = (uint8_t *)&data[0]; b += txtlen;
	
	// копируем в рабочий буфер исходное сообщение
	for (uint8_t i = 0; i < len & txtlen < MESSAGE_MAX_LENGTH; i++) 
	{		
		*b++ = msg[i];
		txtlen++; msgsize += 8;
	}
}


uint32_t * Digest::digest()
{	
	// записываем ещё один бит в конце сообщения
	uint8_t *b = (uint8_t *)&data[0]; b += txtlen;
	*b = 0x80;
	
	// записываем длину сообщения в битах, порядок байт от старшего к младшему
	b = (uint8_t *)&data[15];
	b += 3;
	*b   = msgsize; // наше сообщение никогда не превысит 256 бит
	
	// хешируем блок
	block(&data[0], &hash[0]);
	
	return &hash[0];
}

const uint32_t IVEC[] = {
0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
};

const uint32_t HKEY[] = {
0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void Digest::block(uint32_t *data, uint32_t *hash)
{
	uint32_t a, b, t;
	
	// reset hash
	for (int i = 0; i < 8; i++) hash[i] = IVEC[i];
	
	for (int i = 0; i < 64; i++)
	{
		if ( i < 16 ) 
		{
			t = data[i]; // data as is
		}
		else
		{
			// expand & shift data 
			a = data[(i+1 ) & 15];
			b = data[(i+14) & 15];
			a = a>> 7 ^ a>>18 ^ a>> 3 ^ a<<25 ^ a<<14;
			b = b>>17 ^ b>>19 ^ b>>10 ^ b<<15 ^ b<<13;
			data[i&15] += a + b + data[(i+9) & 15];
			t = data[i&15];
		}

		a = hash[4];
		a =  a>>6 ^ a>>11 ^ a>>25 ^ a<<26 ^ a<<21 ^ a<<7;
		b = (hash[6] ^ (hash[4] & (hash[5] ^ hash[6])));

		t += hash[7] + a + b + HKEY[i];
		
		for (int j = 7; j > 0; j--) hash[j] = hash[j-1];
		hash[4] += t;

		a = (hash[1] & hash[2]) ^ (hash[3] & (hash[1] ^ hash[2]));
		b = hash[1];
		b = b>>2 ^ b>>13 ^ b>>22 ^ b<<30 ^ b<<19 ^ b<<10;
		hash[0] = t + a + b;		
	}
	
	// final gamma
	for (int i = 0; i < 8; i++) hash[i] += IVEC[i];
}

