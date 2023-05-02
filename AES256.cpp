#include "AES256.h"

AES256::AES256(uint8_t key[32])
{
    uint32_t temp;

    for(int i = 0; i < 8; i++) {
        for(int j = 0; j < 3; j++) {
            _rkeys[i] |= key[i*4 + j];
            _rkeys[i] <<= 8;
        }
        _rkeys[i] |= key[i*4 + 3];
    }

    for(int i = 8; i < 60; i++) {
        temp = _rkeys[i-1];
        if(i%8 == 0)
            temp = SubWord((temp << 8) | (temp >> 24)) ^ _Rcon[i/8];
        else if(i%8 == 4)
            temp = SubWord(temp);

        _rkeys[i] = _rkeys[i-8] ^ temp;
    }
}

AES256::~AES256()
{
    for(int i = 0; i < 60; i++)
        _rkeys[i] = 0xff;
}

void AES256::ENC_B(uint8_t dst[16], uint8_t src[16])
{
    block b;
    Swap_BS(b.byte, src);

    AddRoundKey(&b, _rkeys + 0);

    for(int round = 1; round < 14; round++) {
        SubBytes(&b);
        ShiftRows(&b);
        b = MixColumns(b);
        AddRoundKey(&b, _rkeys + round*4);
    }

    SubBytes(&b);
    ShiftRows(&b);
    AddRoundKey(&b, _rkeys + 14*4);

    Swap_BS(dst, b.byte);
}

void AES256::DEC_B(uint8_t dst[16], uint8_t src[16])
{
    block b;
    Swap_BS(b.byte, src);

    AddRoundKey(&b, _rkeys + 14*4);

    for(int round = 13; round > 0; round--) {
        InvShiftRows(&b);
        InvSubBytes(&b);
        AddRoundKey(&b, _rkeys + round*4);
        b = InvMixColumns(b);
    }

    InvShiftRows(&b);
    InvSubBytes(&b);
    AddRoundKey(&b, _rkeys + 0);

    Swap_BS(dst, b.byte);
}

void AES256::Swap_BS(uint8_t dst[16], uint8_t src[16])
{
    for(int i = 0; i < 15; i++)
        dst[i] = src[(i*4)%15];
    dst[15] = src[15];
}

uint8_t AES256::mulm(uint8_t a, uint8_t b)
{
    uint8_t tmp = 0, d = a;
	for (int i = 0; i < 8; i++) {
		tmp ^= d * ((b >> i) & 1);
		d = mulx(d);
	}
	return tmp;
}

uint32_t AES256::SubWord(uint32_t w)
{
    uint32_t res = 0;
    for(int i = 3; i > 0; i--) {
        res |= _SBox[ (w>>(8*i)) & 0xff ];
        res <<= 8;
    }
    res |= _SBox[ w & 0xff ];

    return res;
}

void AES256::SubBytes(block* b)
{
    for(int i = 0; i < 16; i++)
        b->byte[i] = _SBox[b->byte[i]];    
}

void AES256::InvSubBytes(block *b)
{
    for(int i = 0; i < 16; i++)
        b->byte[i] = _InvSBox[b->byte[i]];
}

// в row байты записаны в обратном порядке, т.е.
// r[] = { 0x00, 0x01, 0x02, 0x03 } то
// row = 0x03020100, по этому цикл.сдвиг
// row делается в обратном направлении
void AES256::ShiftRows(block* b)
{
    for(int i = 0; i < 4; i++)
        b->row[i] = (b->row[i] >> i*8) | (b->row[i] << (32 - 8*i));    
}

void AES256::InvShiftRows(block* b)
{
    for(int i = 0; i < 4; i++)
        b->row[i] = (b->row[i] << i*8) | (b->row[i] >> (32 - 8*i));
}

block AES256::MixColumns(block b)
{
    block res;

    for(int c = 0; c < 4; c++) {
        res.state[0][c] = mulm(0x02, b.state[0][c]) ^ mulm(0x03, b.state[1][c]) ^ b.state[2][c] ^ b.state[3][c];
        res.state[1][c] = b.state[0][c] ^ mulm(0x02, b.state[1][c]) ^ mulm(0x03, b.state[2][c]) ^ b.state[3][c];
        res.state[2][c] = b.state[0][c] ^ b.state[1][c] ^ mulm(0x02, b.state[2][c]) ^ mulm(0x03, b.state[3][c]);
        res.state[3][c] = mulm(0x03, b.state[0][c]) ^ b.state[1][c] ^ b.state[2][c] ^ mulm(0x02, b.state[3][c]);
    }

    return res;
}

block AES256::InvMixColumns(block b)
{
    block res;

    for(int c = 0; c < 4; c++) {
        res.state[0][c] = mulm(0x0e, b.state[0][c]) ^ mulm(0x0b, b.state[1][c]) ^ mulm(0x0d, b.state[2][c]) ^ mulm(0x09, b.state[3][c]);
        res.state[1][c] = mulm(0x09, b.state[0][c]) ^ mulm(0x0e, b.state[1][c]) ^ mulm(0x0b, b.state[2][c]) ^ mulm(0x0d, b.state[3][c]);
        res.state[2][c] = mulm(0x0d, b.state[0][c]) ^ mulm(0x09, b.state[1][c]) ^ mulm(0x0e, b.state[2][c]) ^ mulm(0x0b, b.state[3][c]);
        res.state[3][c] = mulm(0x0b, b.state[0][c]) ^ mulm(0x0d, b.state[1][c]) ^ mulm(0x09, b.state[2][c]) ^ mulm(0x0e, b.state[3][c]);
    }
    return res;
}

void AES256::AddRoundKey(block* b, const uint32_t* rkey)
{
   for(int c = 0; c < 4; c++) {
        for(int r = 0; r < 4; r++)
            b->state[r][c] ^= ( (rkey[c] >>(8*(3-r)) & 0xff) );
    }
}
