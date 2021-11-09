#include <iostream>
#include <fstream>

using namespace std;
using std::cout;

void StrToBinary(char* s, bool Text[])
{
	int x = 0;
	for (int i = 0; i < 8; i++)
	{
		// convert each char to ASCII value
		int val = int(s[i]);

		// Convert ASCII value to binary
		string bin = "";
		while (val > 0)
		{
			(val % 2) ? bin.push_back('1') : bin.push_back('0');
			val /= 2;
		}
		while (bin.length() < 8)
		{
			bin.push_back('0');
		}
		reverse(bin.begin(), bin.end());
		for (int j = 0; j < bin.length(); j++)
		{
			Text[x] = (bin[j] == '1') ? 1 : 0;
			x++;
		}
	}
}

void DecToBinary(bool Result[8][4], int val, int o)
{
	string bin = "";
	while (val > 0)
	{
		(val % 2) ? bin.push_back('1') : bin.push_back('0');
		val /= 2;
	}
	while (bin.length() < 4)
	{
		bin.push_back('0');
	}
	reverse(bin.begin(), bin.end());
	for (int j = 0; j < bin.length(); j++)
	{
		Result[o][j] = (bin[j] == '1') ? 1 : 0;
	}
}

void DecToBinaryD(int val, bool Text[], int y)
{
	string bin = "";
	while (val > 0)
	{
		(val % 2) ? bin.push_back('1') : bin.push_back('0');
		val /= 2;
	}
	while (bin.length() < 8)
	{
		bin.push_back('0');
	}
	reverse(bin.begin(), bin.end());
	for (int j = 0; j < 8; j++)
	{
		Text[j+y] = (bin[j] == '1') ? 1 : 0;
	}
}

void BinaryToDec(int ASCII[], bool FinalCipher[])
{
	for (int i = 0, q = 0; i < 64 && q < 8; i += 8, q++)
	{
		ASCII[q] = FinalCipher[i] * 128 + FinalCipher[i + 1] * 64 + FinalCipher[i + 2] * 32 + FinalCipher[i + 3] * 16 + FinalCipher[i + 4] * 8 + FinalCipher[i + 5] * 4 + FinalCipher[i + 6] * 2 + FinalCipher[i + 7];
	}
}

void InitialPermutate(bool Text[], bool CipherText[], int n)
{
	int IP[64] = {
		58,50,42,34,26,18,10,2,
		60,52,44,36,28,20,12,4,
		62,54,46,38,30,22,14,6,
		64,56,48,40,32,24,16,8,
		57,49,41,33,25,17,9,1,
		59,51,43,35,27,19,11,3,
		61,53,45,37,29,21,13,5,
		63,55,47,39,31,23,15,7
	};
	for (int i = 0; i < n; i++)
	{
		CipherText[i] = Text[IP[i] - 1];
	}
}

void Split(bool Left[], bool Right[], int n, bool CipherText[])
{
	for (int i = 0, j = 0; i < n; i++)
	{
		if (i < n/2)
		{
			Left[i] = CipherText[i];
		}
		else
		{
			Right[j] = CipherText[i];
			j++;
		}
	}
}

void singleshift(bool shift[], int n)
{
	bool temp = shift[0];
	for (int i = 0; i < n-1; i++)
	{
		shift[i] = shift[i + 1];
	}
	shift[n-1] = temp;
}

void doubleshift(bool shift[], int n)
{
	bool temp;
	for (int i = 0; i < 2; i++)
	{
		temp = shift[0];
		for (int j = 0; j < n - 1; j++)
		{
			shift[j] = shift[j + 1];
		}
		shift[n - 1] = temp;
	}
}

void GenerateKeys(bool Key[], bool SubKey[16][48])
{
	// The PC1 table 
	int pc1[56] = {
	57,49,41,33,25,17,9,
	1,58,50,42,34,26,18,
	10,2,59,51,43,35,27,
	19,11,3,60,52,44,36,
	63,55,47,39,31,23,15,
	7,62,54,46,38,30,22,
	14,6,61,53,45,37,29,
	21,13,5,28,20,12,4
	};
	// The PC2 table
	int pc2[48] = {
	14,17,11,24,1,5,
	3,28,15,6,21,10,
	23,19,12,4,26,8,
	16,7,27,20,13,2,
	41,52,31,37,47,55,
	30,40,51,45,33,48,
	44,49,39,56,34,53,
	46,42,50,36,29,32
	};
	bool PermutedKey[56];
	bool PermutedKey1[28], PermutedKey2[28], RoundKey[48];	//PermutedKey1=Left; PermutedKey2=Right
	int n, m, x = 1;
	n = 56;
	m = 28;
	//==>Compress from 64 bit keys to 56 bit, using permutation choice 1 (pc1) and removing every 8-th bits
	for (int i = 0; i < n; i++)
	{
		PermutedKey[i] = Key[pc1[i]-1];
	}
	//==>Split key
	Split(PermutedKey1, PermutedKey2, n, PermutedKey);

	//==>Generate 16 Keys
	for (int i = 0; i < 16; i++)
	{
		//For rounds 1, 2, 9, 16 PermutedKey1 and 2 are shifted left by one 
		if (i == 0 || i == 1 || i == 8 || i == 15)
		{
			singleshift(PermutedKey1, m);
			singleshift(PermutedKey2, m);
		}
		else
		{
			doubleshift(PermutedKey1, m);
			doubleshift(PermutedKey2, m);
		}
		//Combine the splitted permuted key
		for (int j = 0, k = 0; j < n; j++)
		{
			if (j < n / 2)
			{
				PermutedKey[j] = PermutedKey1[j];
			}
			else
			{
				PermutedKey[j] = PermutedKey2[k];
				k++;
			}
		}
		//Permute the Permuted key with permutation choice 2 (pc2) and Insert the roundkey to Subkey each round
		for (int l = 0; l < 48; l++)
		{
			SubKey[i][l] = PermutedKey[pc2[l] - 1];
		}
	}
}

void Expand(bool RPt[], bool ER[])
{
	int ExpansionTable[48] = {
	32,1,2,3,4,5,
	4,5,6,7,8,9,
	8,9,10,11,12,13,
	12,13,14,15,16,17,
	16,17,18,19,20,21,
	20,21,22,23,24,25,
	24,25,26,27,28,29,
	28,29,30,31,32,1
	};
	for (int i = 0; i < 48; i++)
	{
		ER[i] = RPt[ExpansionTable[i] - 1];
	}
}

void XOR1(bool ER[], bool SubKey[16][48], bool xored1[], int r)
{
	for (int i = 0; i < 48; i++)
	{
		xored1[i] = (ER[i] != SubKey[r][i]);
	}
}

void SplitEight(bool xored1[], bool Box[8][6])
{
	int a = 0; int b = 0;
	for (int i = 0; i < 48; i++)
	{
		if (a < 6)
		{
			Box[b][a] = xored1[i];
			a++;
		}
		else
		{
			a = 0;
			b++;
			Box[b][a] = xored1[i];
			a++;
		}
	}
}

void Substitute(bool Box[8][6], bool CResult[32])
{
	int SubBox[8][4][16] = {
		{
			{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
			{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
			{4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
			{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
		},
		{
			{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
			{3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
			{0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
			{13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
		},
		{
			{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
			{13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
			{13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
			{1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
		},
		{
			{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
			{13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
			{10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
			{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
		},
		{
			{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
			{14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
			{4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
			{11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
		},
		{
			{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
			{10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
			{9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
			{4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
		},
		{
			{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
			{13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
			{1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
			{6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
		},
		{
			{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
			{1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
			{7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
			{2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
		}
	};
	int row;
	int col;
	int num[8];
	bool Result[8][4];
	//Compress the size of each 8 bits block to 4 bits block each using the S-Box (SubBox)
	for (int i = 0; i < 8; i++)
	{
		row = Box[i][0] * 2 + Box[i][5];
		col = Box[i][1] * 8 + Box[i][2] * 4 + Box[i][3] * 2 + Box[i][4];
		num[i] = SubBox[i][row][col];
		DecToBinary(Result, num[i], i);		//Convertion from decimal to binary
	}
	//Combine Result from seperate 4 bits block to a single 32 bits block
	for (int j = 0, a = 0; j < 32 && a < 8; j += 4, a++)
	{
		for (int k = 0; k < 4; k++)
		{
			CResult [j+k] = Result[a][k];
		}
	}
}

void PPermutation(bool PResult[], bool SubRes[])
{
	int P[32] = {
		16,7,20,21,29,12,28,17,
		1,15,23,26,5,18,31,10,
		2,8,24,14,32,27,3,9,
		19,13,30,6,22,11,4,25
	};
	for (int i = 0; i < 32; i++)
	{
		PResult[i] = SubRes[P[i] - 1];
	}
}

void XOR2(bool LPt[], bool PResult[], bool xored2[])
{
	for (int i = 0; i < 32; i++)
	{
		xored2[i] = (LPt[i] != PResult[i]);
	}
}

void FinalPermutation(bool CipherText[], bool FinalCipher[])
{
	int FP[64] = {
		40,8,48,16,56,24,64,32,
		39,7,47,15,55,23,63,31,
		38,6,46,14,54,22,62,30,
		37,5,45,13,53,21,61,29,
		36,4,44,12,52,20,60,28,
		35,3,43,11,51,19,59,27,
		34,2,42,10,50,18,58,26,
		33,1,41,9,49,17,57,25
	};
	for (int i = 0; i < 64; i++)
	{
		FinalCipher[i] = CipherText[FP[i] - 1];
	}
}

int main()
{
	//====================================DES ENCRYPTION=======================================================//
	/*
	 Step:
	  Generating 16 different subkey to be used for 16 round of encryption:
	  1) Permutate the 64 bits block of plain text key using the permutation choice 1,
		 then we get a 56 bits block of key
	  2) Split the 56 bits key into two 28 bits key block
	  3) Circularly left shift both of the key blocks,
		 and the amount of digits shifted are based on the number of subkey/rounds
		 for round 1, 2, 9, and 16 they are all circularly shifted by 1, the rest by 2.
	  4) Combine the right and left shifted key to 56 bits block key
	  5) Permute the shifted key with permutation choice 2, then we get 48 bits block of subkey
	  6) Step 3-4 are done 16 times to create 16 differents subkey for each round of encryption

	  DES encryption step:
	  1) Do initial permutation to the plain 64 bits text
	  2) Split the permutation result into 2 32 bits block called as Right Permutation & Left permutation
	  3) Expand the right permutation from 32 bits block to 48 bits block using the expansion table
	  4) Do XOR logical function between 48 bits block of expanded right permutation with the subkey
		 for this round
	  5) Split the result into 8 blocks of 6 bits block, then using the substitution box (S-Box),
		 we will get a reduced 8 blocks of 4 bits block
		 Substitute:
		 1) For each block have their own S-Box to substitute
		 2) From 6 bits, take the first and last bits and convert it to decimal then we set it as
			the number of row, second till fifth digit will be the number of column
		 3) Check the S-Box for that row and column and we take the number in that row and column
			as the result then convert the result to binary then we will get the 8 blocks of 4 bits block
			then combine it into single 32 bits block result
	  6) Permute the result with the permutation (P)
	  7) Do the XOR operation between the permutation result with the initial left permutation
	  8) Step 3-7 are done 16 times (USE THE DIFFERENT SUBKEY FOR EACH ROUND(USE SUBKEY FOR THAT ROUND))
	  9) After 16 round swap the position of the right and left part, then combine it into
		 one single 64 bits block cipher text
	  10) Then permutate the cipher text with the final permutation to achieve the encrypted binary text
	  11) Convert the binary to text using ASCII-encoding
	  DONE!!
	*/
	ofstream Output;
	char s[8], key[8];
	string encryptedtext[8], dencryptedtext[8];
	bool Text[64], Key[64], SubKey[16][48];
	bool RPt[32], LPt[32], ER[48];
	bool Box[8][6], SubRes[32];
	bool xored1[48], xored2[32], PResult[32], CipherText[64], FinalCipher[64];
	bool temp;
	int ASCII[8];
	int x, n;
	
	n = 64;

	Output.open("Result.txt");

	cout << "ENTER TEXT TO ENCRYPT: ";
	cin >> s;
	cout << "ENTER KEY: ";
	cin >> key;
	cout << endl << endl;

	//Output the input text to the file
	Output << "TEXT TO ENCRYPT: ";
	for (int i = 0; i < 8; i++)
	{
		Output << s[i];
	}
	Output << endl << "KEY: ";
	for (int i = 0; i < 8; i++)
	{
		Output << key[i];
	}
	Output << endl << endl ;
	
	//==>Convert String s to bool array "Text" consist of binary code from ASCII of the string
	StrToBinary(s, Text);

	//==>Convert String key to bool array "Key" consist of binary code from ASCII of the string
	StrToBinary(key, Key);

	//Generate 16 subkey for each round of encryption
	GenerateKeys(Key, SubKey);

	//==>DES Encryption process start from here
	//==>Initial Permutation
	InitialPermutate(Text, CipherText, n);
	
	//==>Split into 2 32 bits block each
	Split(LPt, RPt, n, CipherText);
	
	//==>16 round of encryption starts here
	for (int r = 0; r < 16; r++)
	{
		//Expand right set to 48 bits from 32 bits
		Expand(RPt, ER);

		//XOR expanded right with this round subkey
		XOR1(ER, SubKey, xored1, r);
		
		//Split result to eight subset
		SplitEight(xored1, Box);

		//Subtitute to get 32 bits set
		Substitute(Box, SubRes);

		//Another Permutation
		PPermutation(PResult, SubRes);

		//XOR with Left Permutation (LPt)
		XOR2(LPt, PResult, xored2);

		//Move initial RPt to the LPt and assign the new RPt with the XOR result we got
		for (int i = 0; i < 32; i++)
		{
			LPt[i] = RPt[i];
			RPt[i] = xored2[i];
		}
	}
	
	//==>Swap Left and Right
	for (int i = 0; i < 32; i++)
	{
		temp = LPt[i];
		LPt[i] = RPt[i];
		RPt[i] = temp;
	}
	
	//==>Combine Left and Right result
	for (int i = 0, j = 0; i < 64; i++)
	{
		if (i < 32)
		{
			CipherText[i] = LPt[i];
		}
		else 
		{
			CipherText[i] = RPt[j];
			j++;
		}
	}
	
	//==>Last Permutation
	FinalPermutation(CipherText, FinalCipher);
	
	//==>Conversion from binary to decimal to determine the ASCII-encoding 
	//   to get the plain 64 bits plain encrypted text
	BinaryToDec(ASCII, FinalCipher);

	//==>Print out and print to file the ASCII-Encoding result and the plain encrypted text
	cout << endl << "DES ENCRYPTION" << endl << endl << "ASCII-Encoding" << '\t' << "Char" << endl;
	Output << "DES ENCRYPTION" << endl << endl << "ASCII-Encoding" << '\t' << "Char" << endl;
	for (int i = 0; i < 8; i++)
	{
		cout << ASCII[i] << "\t\t ";
		Output << ASCII[i] << "\t\t ";
		encryptedtext[i] = static_cast<char>(ASCII[i]);
		cout << encryptedtext[i] << endl;
		Output << encryptedtext[i] << endl;
	}
	Output.close();


	//====================================DES DECRYPTION=======================================================//

	Output.open("DResult.txt");
	cout << endl << endl << endl;
	int DASCII[8];
	//Enter the ASCII code that we got after we encrypt
	//Also output the input text to the file
	cout << "ENTER ASCII CODE TO DECRYPT: ";
	Output << "ASCII CODE TO DECRYPT:" << endl;
	for (int i = 0, y = 0; i < 8 && y < 64; i++,y+=8)
	{
		cin >> DASCII[i];
		DecToBinaryD(DASCII[i], Text, y);
		Output << DASCII[i] << "  ";
	}
	Output << endl << endl;
	
	//==>DES Decryption process start from here
	//==>Initial Permutation
	InitialPermutate(Text, CipherText, n);

	//==>Split into 2 32 bits block each
	Split(LPt, RPt, n, CipherText);

	//First we need to reverse the order of the subkey since we are doing decryption process
	int q = 0;
	int d = 15;
	while (d > q)
	{
		for (int j = 0; j < 48; j++)
		{
			temp = SubKey[d][j];
			SubKey[d][j] = SubKey[q][j];
			SubKey[q][j] = temp;
		}
		d--;
		q++;
	}

	//==>16 round of encryption starts here
	for (int r = 0; r < 16; r++)
	{
		//Expand right set to 48 bits from 32 bits
		Expand(RPt, ER);

		//XOR expanded right with this round subkey
		XOR1(ER, SubKey, xored1, r);
		
		//Split result to eight subset
		SplitEight(xored1, Box);

		//Subtitute to get 32 bits set
		Substitute(Box, SubRes);

		//Another Permutation
		PPermutation(PResult, SubRes);

		//XOR with Left Permutation (LPt)
		XOR2(LPt, PResult, xored2);
		
		//Move initial RPt to the LPt and assign the new RPt with the XOR result we got
		for (int i = 0; i < 32; i++)
		{
			LPt[i] = RPt[i];
			RPt[i] = xored2[i];
		}
	}

	//==>Swap Left and Right
	for (int i = 0; i < 32; i++)
	{
		temp = LPt[i];
		LPt[i] = RPt[i];
		RPt[i] = temp;
	}

	//==>Combine Left and Right result
	for (int i = 0, j = 0; i < 64; i++)
	{
		if (i < 32)
		{
			CipherText[i] = LPt[i];
		}
		else
		{
			CipherText[i] = RPt[j];
			j++;
		}

	}

	//==>Last Permutation
	FinalPermutation(CipherText, FinalCipher);

	//==>Conversion from binary to decimal to determine the ASCII-encoding 
	//   to get the plain 64 bits plain/decrypted text
	BinaryToDec(ASCII, FinalCipher);

	//==>Print out the ASCII-Encoding result and the plain decrypted text
	cout << "DES DECRYPTION" << endl << endl << "ASCII-Encoding" << '\t' << "Char" << endl;
	Output << "DES DECRYPTION" << endl << endl << "ASCII-Encoding" << '\t' << "Char" << endl;
	for (int i = 0; i < 8; i++)
	{
		if (ASCII[i] == 0)
		{
			continue;
		}
		cout << ASCII[i] << "\t\t ";
		Output << ASCII[i] << "\t\t ";
		dencryptedtext[i] = static_cast<char>(ASCII[i]);
		cout << dencryptedtext[i] << endl;
		Output << dencryptedtext[i] << endl;
	}
	Output.close();
	return 0;
}