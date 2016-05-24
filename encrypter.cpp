#include "stdafx.h"
#include "encrypter.h"

encrypter::encrypter()
{
}


encrypter::~encrypter()
{
}

void encrypter::KeyExpansion(unsigned char* key, Level level = Level::weak)
{
	int n = 16;
	int b = 176;
	int rc = 11;

	switch (level) {
		case Level::weak: {
			n = 16;
			b = 176;
			break;
		}
		case Level::medium: {
			n = 24;
			b = 208;
			rc = 13;
			break;
		}
		case Level::strong: {
			n = 32;
			b = 240;
			rc = 15;
		}
	}

	for (int i = 0; i < rc; i++)
	{
		unsigned char* expandedKey = new unsigned char[b];
		int rconVal = 1;
		int l = n;

		while (l < b) {
			//Copy key
			for (int j = 0; j < n; j++) 
			{
				expandedKey[j] = key[j];
			}
			
			//1.1
			unsigned char t[4];
			//1.2
			for (int j = 0; j < 4; j++) {
				t[j] = expandedKey[l - n];
			}
			//1.3
			KeyScheduleCore(t, rconVal);
			//1.4
			++rconVal;

			//1.5
			CopyTemp(expandedKey, t, l, n);
			l += 4;

			//2.1/2.2
			for (int i = 0; i < 3; i++) 
			{
				AssignTemp(expandedKey, t, l, n);
				CopyTemp(expandedKey, t, l, n);
				l += 4;
			}

			//3.1-3.2
			if (level == Level::strong)
			{
				AssignTemp(expandedKey, t, l, n);
				for (int j = 0; j < 3; j++) 
				{
					t[j] = sBox[t[j]];
				}
				CopyTemp(expandedKey, t, l, n);
				l += 4;
			}
			//3.1-3.2 or 4.1-4.2
			else if (level >= Level::medium)
			{
				int c = level == Level::medium ? 2 : 3;
				for (int j = 0; j < c; j++)
				{
					AssignTemp(expandedKey, t, l, n);
					CopyTemp(expandedKey, t, l, n);
					l += 4;
				}
			}
		}

		roundKeys[i] = expandedKey;
	}
}

void encrypter::KeyScheduleCore(unsigned char* input, int i)
{
	unsigned char output[4];

	output[0] = input[3];
	output[1] = input[0];
	output[2] = input[1];
	output[3] = input[2];

	output[0] = sBox[output[0]];
	output[1] = sBox[output[1]];
	output[2] = sBox[output[2]];
	output[3] = sBox[output[3]];

	output[0] ^= rcon[i];

	for (int i = 0; i < 4; i++) 
	{
		input[i] = output[i];
	}
}

//Step 1.5 / 2.2
void encrypter::CopyTemp(unsigned char* input, unsigned char* tmp, int ekl, int ikl)
{
	for (int j = 0; j < 4; j++) 
	{
		input[ekl + j] = input[ekl - ikl + j] ^ tmp[j];
	}
}

//Step 2.1
void encrypter::AssignTemp(unsigned char* input, unsigned char* tmp, int ekl, int ikl)
{
	for (int j = ekl - 4; j < ekl; j++)
	{
		tmp[j] = input[j];
	}
}

void encrypter::SubBytes(unsigned char* state)
{
	for (int i = 0; i < 16; i++)
	{
		state[i] = sBox[i];
	}
}

//We shift the rows as specificed by AES
//The first row isn't shifted
//The second row is shifted once
//The third row is shifted twice
//The fourth is shifted three times
//We will move over blocks as they are shifted

//i.e
//{{0,4,8,12},
// {1,5,9,13},
// {2,6,10,14},
// {3,7,11,15}}
//Becomes
//{{0,4,8,12},
// {5,9,13,1},
// {10,14,2,6},
// {15,3,7,11}}

void encrypter::ShiftRows(unsigned char* state)
{
	unsigned char tmp[16];

	tmp[0] = state[0];
	tmp[1] = state[5];
	tmp[2] = state[10];
	tmp[3] = state[15];

	tmp[4] = state[4];
	tmp[5] = state[9];
	tmp[6] = state[14];
	tmp[7] = state[3];

	tmp[8] = state[8];
	tmp[9] = state[13];
	tmp[10] = state[2];
	tmp[11] = state[7];

	tmp[12] = state[12];
	tmp[13] = state[1];
	tmp[14] = state[6];
	tmp[15] = state[11];

	for (int i = 0; i < 16; i++)
	{
		state[i] = tmp[i];
	}
}

void encrypter::AddRoundKey(unsigned char* state, unsigned char* roundKey) 
{
	for (int i = 0; i < 16; i++)
	{
		state[i] ^= roundKey[i];
	}
}

void encrypter::MixColumns(unsigned char* state)
{
	unsigned char a[4];
	unsigned char b[4];
	unsigned char c;
	unsigned char h;

	for (c = 0; c < 4; c++)
	{
		a[c] = state[c];
		//h = (unsigned char)((signed char)state[c] >> 7);
		//b[c] = state[c] << 1;
		//b[c] ^= 0x1b & h;
	}

	state[0] = mix2[a[0]] ^ a[3] ^ a[2] ^ mix3[a[1]]; /* 2 * a0 + a3 + a2 + 3 * a1 */
	state[1] = mix2[a[1]] ^ a[0] ^ a[3] ^ mix3[a[2]]; /* 2 * a1 + a0 + a3 + 3 * a2 */
	state[2] = mix2[a[2]] ^ a[1] ^ a[0] ^ mix3[a[3]]; /* 2 * a2 + a1 + a0 + 3 * a3 */
	state[3] = mix2[a[3]] ^ a[2] ^ a[1] ^ mix3[a[0]]; /* 2 * a3 + a2 + a1 + 3 * a0 */

	//state[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]; /* 2 * a0 + a3 + a2 + 3 * a1 */
	//state[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]; /* 2 * a1 + a0 + a3 + 3 * a2 */
	//state[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]; /* 2 * a2 + a1 + a0 + 3 * a3 */
	//state[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]; /* 2 * a3 + a2 + a1 + 3 * a0 */
}

unsigned char* encrypter::encrypt(unsigned char* message, unsigned char* key, Level level = Level::weak) 
{
	unsigned char state[16];
	for (int i = 0; i < 16; i++)
	{
		state[i] = message[i];
	}

	int numberOfRounds = 1;

	switch (level) {
		case Level::weak: {
			numberOfRounds = 10;
			break;
		}
		case Level::medium: {
			numberOfRounds = 12;
			break;
		}
		case Level::strong: {
			numberOfRounds = 14;
		}
	}
	
	KeyExpansion(key);
		
	for (int i = 0; i < numberOfRounds; i++)
	{
		SubBytes(state);
		ShiftRows(state);
		MixColumns(state);
		AddRoundKey(state, roundKeys[i]);
	}

	SubBytes(state);
	ShiftRows(state);
	AddRoundKey(state, key);
	DisposeKeys(numberOfRounds + 1);

	return state;
}

unsigned char* encrypter::decrypt(unsigned char* message, unsigned char* key, Level level = Level::weak)
{

	return message;
}

void encrypter::DisposeKeys(int roundCount)
{
	for (int i = 0; i < roundCount; i++) {
		delete[] roundKeys[i];
	}
}