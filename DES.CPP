#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

unsigned char plain1[65],plain2[65],cipher1[65],cipher2[65],
			  			plain3[65],plain4[65],cipher3[65],cipher4[65],
			  			plain5[65],plain6[65],cipher5[65],cipher6[65],
			  			J[49],P1[57],K[65],unknown[8],Brute[8],
			  			FE[49],Knew[49],
			  			L0[33],R0[33],L1[33],R1[33],L2[33],R2[33],L3[33],R3[33],tmp[33],
			  			after_left[29],after_right[29];
unsigned char test_cipher[65];
static int counter[8][64],max[8];

const unsigned char P[]=
{
  0,
  16  ,7	,20	,21	,29	,12	,28	,17	,1	,15	,23	,26	,5	,18	,31	,10
  ,2	,8	,24	,14	,32	,27	,3	,9	,19	,13	,30	,6	,22	,11	,4	,25
};

const unsigned char P_inverse[]=
{
  0,
  9,17,23,31,13,28,2,18,24,16,30,6,26,20,10,1,8,14,25,3,4,29,11,19,32,12,22,7,5,27,15,21
};

const unsigned char E[]=
{
  0,
  32	,1	,2	,3	,4	,5	,4	,5	,6	,7	,8	,9
  ,8	,9	,10	,11	,12	,13	,12	,13	,14	,15	,16	,17
  ,16	,17	,18	,19	,20	,21	,20	,21	,22	,23	,24	,25
  ,24	,25	,26	,27	,28	,29	,28	,29	,30	,31	,32	,1
};

const unsigned char S[8][4][16] = {
  14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
   0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
   4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
  15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13,

  15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
   3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
   0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
  13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9,

  10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
  13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
  13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
   1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12,

   7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
  13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
  10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
   3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14,

   2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
  14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
   4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
  11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3,

  12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
  10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
   9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
   4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13,

   4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
  13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
   1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
   6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12,

  13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
   1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
   7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
   2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
};

const unsigned char PC1[]=
{
  0,
  57,	49,	41,	33,	25,	17,	9,	1,	58,	50,	42,	34,	26,	18,
  10,	2,	59,	51,	43,	35,	27,	19,	11,	3,	60,	52,	44,	36,
  63,	55,	47,	39,	31,	23,	15,	7,	62,	54,	46,	38,	30,	22,
  14,	6,	61,	53,	45,	37,	29,	21,	13,	5,	28,	20,	12,	4
};
const unsigned char PC1_shift[]=
{
  0,	

	25,	17,	9,	1,	58,	50,	42,	34,	26,	18,
  10,	2,	59,	51,	43,	35,	27,	19,	11,	3,	60,	52,	44,	36,
  57,	49,	41,	33,
	
	31,	23,	15,	7,	62,	54,	46,	38,	30,	22,
  14,	6,	61,	53,	45,	37,	29,	21,	13,	5,	28,	20,	12,	4 ,
  63,	55,	47,	39	

};
const unsigned char PC2[]=
{
  0,
  14,	17,	11,	24,	1,	5,	3,	28,	15,	6,	21,	10,
  23,	19,	12,	4,	26,	8,	16,	7,	27,	20,	13,	2,
  41,	52,	31,	37,	47,	55,	30,	40,	51,	45,	33,	48,
  44,	49,	39,	56,	34,	53,	46,	42,	50,	36,	29,	32
  };
const unsigned char shift[]=
{
  0,
  1,	2,	4,	6,	8,	10,	12,	14,	15,	17,	19,	21,	23,	25,	27,	28
};

const unsigned char IP[]=
{
  0,
  58	,50	,42	,34	,26	,18	,10	,2	,60	,52	,44	,36	,28	,20	,12	,4
  ,62	,54	,46	,38	,30	,22	,14	,6	,64	,56	,48	,40	,32	,24	,16	,8
  ,57	,49	,41	,33	,25	,17	,9	,1	,59	,51	,43	,35	,27	,19	,11	,3
  ,61	,53	,45	,37	,29	,21	,13	,5	,63	,55	,47	,39	,31	,23	,15	,7
};

const unsigned char IP_inverse[]=
{
  0,
  40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
  38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
  36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
  34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25
};

void Xor32bit(unsigned char  a[33],unsigned char  b[33],unsigned char c[33])
{
	int i;
	for(i=1;i<=32;i++)
		if(a[i]==b[i])
			c[i]=0;
		else
			c[i]=1;
}


void Xor48bit(unsigned char  a[49],unsigned char  b[49],unsigned char c[49])
{
	int i;
	for(i=1;i<=48;i++)
		if(a[i]==b[i])
			c[i]=0;
		else
			c[i]=1;
}

void compute_P(unsigned char  a[33],unsigned char  b[33])
{
	int i;
	for(i=1;i<=32;i++)
		b[i] = a[ P[i] ];
}
//compute P inverse = compute C'
void compute_p_inverse(unsigned char  a[33],unsigned char  b[33])
{
	int i;
	for(i=1;i<=32;i++)
		b[i] = a[ P_inverse[i] ];
}

void compute_E(unsigned char  a[33],unsigned char  b[49])
{
	int i;
	for(i=1;i<=48;i++)
		b[i] = a[ E[i] ];
}

void compute_subkey(unsigned char K[65], unsigned char Knew[49], int num)
{
	unsigned char tmp[57],left[29],right[29],real_left[29],real_right[29],tmp_K[57];
	int i;
	//做PC1(K)
	for(i=1;i<=56;i++)
		tmp[i] = K[ PC1[i] ];
	for(i=1;i<=28;i++)
	{
		left[i]=tmp[i];
		right[i]=tmp[i+28];
	}
	int j=1;
	for(i=1;i<=28;i++)
	{
		if(i%8!=0)
		{
			real_left[j]=left[i];
			real_right[j]=right[i];
			j++;
		}
	}
	//做shift
	for(i=1;i<=28;i++)
	{
		if( ( i- shift[num] ) > 0  )
		{
			after_left[i- shift[num]  ] = left[i];
			after_right[i- shift[num]  ] = right[i];
		}
	}
	for(i=1;i<=shift[num] ;i++)
	{
		after_left[28-shift[num]+i]=real_left[i];
		after_right[28-shift[num]+i]=real_right[i];
	}
	for(i=1;i<=28;i++)
	{
		tmp_K[i]=after_left[i];
		tmp_K[i+28]=after_right[i];
	}
	//做PC2
	for(i=1;i<=48;i++)
		Knew[i] = tmp_K[ PC2[i] ];
//	printf("\n");
}

void compute_S(unsigned char  a[49],unsigned char  b[33])
{
	int k,j,column,row,s_value,rem;

	for(j=0;j<=7;j++)
	{
		
		//計算Sj()內容的10進位值
			column=0;
			for(k=2;k<=5;k++)
			{
				column+=(int)pow(2,5-k)*a[j*6+k];
			}
			row=2*a[j*6+1]+a[j*6+6];

			s_value=S[j][row][column];   
			
			//計算Sj()內容			4 bits存在 b[33]
			for(k=0;k<=3;k++)      
			{
				rem = s_value%2;
				s_value = (int) s_value/2;
				b[j*4+4-k] = rem;
			}
	}
}
void do_IP(unsigned char plain[65],unsigned char L0[33],unsigned char R0[33])
{
	unsigned char tmp[65];
	int i;

	for(i=1;i<=64;i++)
		tmp[i] = plain[ IP[i] ];
	for(i=1;i<=32;i++)
	{
		L0[i]=tmp[i];
	}
	for(i=33;i<=64;i++)
	{
		R0[i-32]=tmp[i];
	}
}

void do_IP_inverse(unsigned char R3[33],unsigned char L3[33],unsigned char cipher[65])
{
	unsigned char tmp[65];
	int i;

	for(i=1;i<=32;i++)
	{
		tmp[i]=R3[i];
	}
	for(i=1;i<=32;i++)
	{
		tmp[i+32]=L3[i];
	}
	for(i=1;i<=64;i++)
		cipher[IP[i]] = tmp[i];
 printf("\n");
}

//compute E
void expansion(unsigned char a[65],unsigned char b[49])
{
	int i;

//	unsigned char tmp[33];   //copy "a" 65 bits 的左半到 "tmp" 33 bits
//	for(i=1;i<=32;i++)
//		tmp[i]=a[i];

	for(i=1;i<=48;i++)
		b[i] = a[ E[i] ];
}

//compute test                  E1[]:E               E2[]:E*              C'
void compute_test(unsigned char E1[49],unsigned char E2[49],unsigned char C[33])
{
	int i,j,k,column,row,s_value/*s是10進位*/,rem/*餘數*/;
	int flag,value;
	unsigned char E3[49];                       //E3 為 E' = E xor E*

    unsigned char Bj[7] , Sj_Bj[5] , Bj_tmp[7], Sj_Bj_tmp[5] , test[5] , result[5];

	//計算E3 : E' = E xor E*
	for(j=1;j<=48;j++)
		if(E1[j]== E2[j])
			E3[j]=0;
		else
			E3[j]=1;

	for(j=0;j<=7;j++)
	{
		for(i=0;i<64;i++)
		{
			value=i;
			for(k=0;k<=5;k++)      //計算Bj內容 6 bits
			{
				rem = value%2;
				value=(int)value/2;
				Bj[6-k] = rem;
			}
		//計算Sj(Bj)內容的10進位值
			column=0;
			for(k=2;k<=5;k++)
			{
				column+=(int)pow(2,5-k)*Bj[k];
			}
			row=2*Bj[1]+Bj[6];

			s_value=S[j][row][column];   
			
			//計算Sj(Bj)內容			4 bits存在 Sj_Bj[5]
			for(k=0;k<=3;k++)      
			{
				rem = s_value%2;
				s_value = (int) s_value/2;
				Sj_Bj[4-k] = rem;
			}
			// 計算 Bj xor Ej' 內容       6 bits  存在 Bj_tmp[7] 
			for(k=1;k<=6;k++)
			{
				if( Bj[k] == E3[j*6+k] )
					Bj_tmp[k]=0;
				else
					Bj_tmp[k]=1;
			}
			//計算Sj(Bj_tmp)內容的10進位值
			column=0;
			for(k=2;k<=5;k++)
			{
				column+=(int)pow(2,5-k)*Bj_tmp[k];
			}
			row=2*Bj_tmp[1]+Bj_tmp[6];

			s_value=S[j][row][column];   
			
			//計算Sj(Bj_tmp)內容  4 bits  存在 Sj_Bj_tmp[5]
			for(k=0;k<=3;k++)      
			{
				rem = s_value %2;
				s_value = (int) s_value /2;
				Sj_Bj_tmp[4-k] = rem;
			}
			//計算 " Sj(Bj) xor Sj(Bj_tmp) " 存在 test[5] 是否= Cj'
			for(k=1;k<=4;k++)
			{
				if(Sj_Bj[k]==Sj_Bj_tmp[k])
					test[k]=0;
				else
					test[k]=1;
			}
			flag=0;

			if(test[1]==C[j*4+1] && test[2]==C[j*4+2] && test[3]==C[j*4+3] && test[4]==C[j*4+4] )
				flag=1;
			//是的話  作 Bj xor Ej
			if(flag==1)
			{
				for(k=1;k<=6;k++)
				{
					if( Bj[k] == E1[j*6+k] )
						result[k]=0;
					else
						result[k]=1;
				}
				//算出result對應的counter 並+1
				int num_counter=0;
				for(k=1;k<=6;k++)
				{
					num_counter+=(int)pow(2,6-k)*result[k];
				}
				counter[j][num_counter]++;
			}			
		}
	}
	value = 0;
}

//將輸入的16進位轉成64 bit binary    before[17]:0 ~ 15有值  after[0]不存值 1 ~64
void Plain_2_binary( char before[17],unsigned char after[65])
{
	int i,num;
	for(i=0;i<=15;i++)		
	{
		switch (before[i])      //hex_2_dec :num
		{
		case 'A':
			num=10;
			break;
		case 'B':
			num=11;
			break;
		case 'C':
			num=12;
			break;
		case 'D':
			num=13;
			break;
		case 'E':
			num=14;
			break;
		case 'F':
			num=15;
			break;
		default:
			num=before[i];
		}
		int rem,j;           //rem餘數
		for(j=0;j<=3;j++)
		{
			rem = num%2;
			num = (int)num/2;
			after[i*4+(4-j)] = rem;
		}
	}
}

//compute R3'=R3 xor R3*
void R3_xor(unsigned char a[65],unsigned char b[65], unsigned char c[33])
{
	int i;
	for(i=33;i<=64;i++)
	{
		if(a[i]==b[i])
			c[i-32]=0;
		else 
			c[i-32]=1;
	}
}
//compute L0'=L0 xor L0*
void L0_xor(unsigned char a[65],unsigned char b[65], unsigned char c[33])
{
	int i;
	for(i=1;i<=32;i++)
	{
		if(a[i]==b[i])
			c[i]=0;
		else 
			c[i]=1;
	}
}
//數字轉到6 bits binary
void digit_2_6bits(int n,int digit,unsigned char J[49])
{
	int i,rem;
	for(i=1;i<=6;i++)
		{
			rem = digit %2;
			digit = (int)digit/2;
			J[n*6+(7-i)] = rem;
		}
}
//F function
void compute_f(unsigned char R[32],unsigned char K[65],int shift_count,unsigned char output[32])
{
	unsigned char before_S[49],before_P[33];
	compute_E(R,FE);
	compute_subkey(K,Knew,shift_count);
	Xor48bit(FE,Knew,before_S);
	compute_S(before_S,before_P);
	compute_P(before_P,output);
}
// assign B to A
void assign(unsigned char A[33],unsigned char B[33])
{
	int i;
	for(i=1;i<=32;i++)
	{
		A[i]=B[i];
	}
}
//測試KEY
int runDES(unsigned char plain[65], unsigned char cipher[65], unsigned char K[65]  )
{
	int i;
//	do_IP(plain,L0,R0);
	
	for(i=1;i<=32;i++)
	{
		L0[i]=plain[i];
		R0[i]=plain[i+32];
	}
	
	assign(L1,R0);
	compute_f(R0,K,1,tmp);
	Xor32bit(L0,tmp,R1);
	assign(L2,R1);
	compute_f(R1,K,2,tmp);
	Xor32bit(L1,tmp,R2);
	compute_f(R2,K,3,tmp);
	Xor32bit(L2,tmp,R3);
	assign(L3,R2);
//	do_IP_inverse(R3,L3,test_cipher);
	
	for(i=1;i<=32;i++)
	{
		test_cipher[i]=L3[i];
		test_cipher[i+32]=R3[i];
	}
	
	int flag=1;
	for(i=1;i<=64;i++)
	{
		if(test_cipher[i]!=cipher[i]){
			flag=0;
			break;
		}
	}
	if(flag==1)
		return 1;
	else
		return 0;
//		printf("\n");

}

void main()
{
  char input1[17],input2[17],input3[17],input4[17],input5[17],input6[17],
			 input7[17],input8[17],input9[17],input10[17],input11[17],input12[17],
			 Real_key[17];
	unsigned char tmp1[33],tmp2[33],tmp3[33],tmp4[33],L1[49],L2[49];
	strcpy(input1,"748502CD38451097");
	strcpy(input2,"3874756438451097");
	strcpy(input3,"03C70306D8A09F10");
	strcpy(input4,"78560A0960E6D4CB");
	strcpy(input5,"486911026ACDFF31");
	strcpy(input6,"375BD31F6ACDFF31");
	strcpy(input7,"45FA285BE5ADC730");
	strcpy(input8,"134F7915AC253457");
	strcpy(input9,"357418DA013FEC86");
	strcpy(input10,"12549847013FEC86");
	strcpy(input11,"D8A31B2F28BBC5CF");
	strcpy(input12,"0F317AC2B23CB944");

	printf("(1)\n\n     Input:\n\n");
	printf("--------------------------------------------------\n");
	printf("	The plaintext1  is  %s \n",input1);
	printf("	The plaintext2  is  %s \n",input2);
	printf("	The ciphertext1 is  %s \n",input3);
	printf("	The ciphertext2 is  %s \n",input4);
	printf("	The plaintext3  is  %s \n",input5);
	printf("	The plaintext4  is  %s \n",input6);
	printf("	The ciphertext3 is  %s \n",input7);
	printf("	The ciphertext4 is  %s \n",input8);
	printf("	The plaintext5  is  %s \n",input9);
	printf("	The plaintext6  is  %s \n",input10);
	printf("	The ciphertext5 is  %s \n",input11);
	printf("	The ciphertext6 is  %s \n",input12);
	printf("--------------------------------------------------\n");

	Plain_2_binary(input1,plain1);
	Plain_2_binary(input2,plain2);
	Plain_2_binary(input3,cipher1);
	Plain_2_binary(input4,cipher2);
	Plain_2_binary(input5,plain3);
	Plain_2_binary(input6,plain4);
	Plain_2_binary(input7,cipher3);
	Plain_2_binary(input8,cipher4);
	Plain_2_binary(input9,plain5);
	Plain_2_binary(input10,plain6);
	Plain_2_binary(input11,cipher5);
	Plain_2_binary(input12,cipher6);
//ok

	R3_xor(cipher1,cipher2,tmp1);		// tmp1:  R3'=R3 xor R3*
	L0_xor(plain1,plain2,tmp2);			// tmp2:  L0'=L0 xor L0*
	Xor32bit(tmp1,tmp2,tmp3);			// tmp3:  R3' xor L0'
	compute_p_inverse(tmp3,tmp4);		// tmp4:  C' = P^-1(R3' xor L0')
	expansion(cipher1,L1);				// L1:    E=E(L3)
	expansion(cipher2,L2);				// L2:	  E*=E(L3*)
	compute_test(L1,L2,tmp4);			// compute test(E,E*,C')

	R3_xor(cipher3,cipher4,tmp1);		// tmp1:  R3'=R3 xor R3*
	L0_xor(plain3,plain4,tmp2);			// tmp2:  L0'=L0 xor L0*
	Xor32bit(tmp1,tmp2,tmp3);			// tmp3:  R3' xor L0'
	compute_p_inverse(tmp3,tmp4);		// tmp4:  C' = P^-1(R3' xor L0')
	expansion(cipher3,L1);				// L1:    E=E(L3)
	expansion(cipher4,L2);				// L2:	  E*=E(L3*)
	compute_test(L1,L2,tmp4);			// compute test(E,E*,C')

	R3_xor(cipher5,cipher6,tmp1);		// tmp1:  R3'=R3 xor R3*
	L0_xor(plain5,plain6,tmp2);			// tmp2:  L0'=L0 xor L0*
	Xor32bit(tmp1,tmp2,tmp3);			// tmp3:  R3' xor L0'
	compute_p_inverse(tmp3,tmp4);		// tmp4:  C' = P^-1(R3' xor L0')
	expansion(cipher5,L1);				// L1:    E=E(L3)
	expansion(cipher6,L2);				// L2:	  E*=E(L3*)
	compute_test(L1,L2,tmp4);			// compute test(E,E*,C')

	printf("\n");
	printf("\n\n(2)\n\n     The contents of J1 to J8 :");
	printf("\n");
	int i,j;
	for(i=0;i<8;i++)
	{
		printf("\n\n");
		printf("The contents of J%d :",i+1);
		printf("\n");
		printf("--------------------------------------------------\n");
		for(j=0;j<64;j++)
		{
			if((j % 16) == 0) printf("\n");
			printf("%d ",counter[i][j]);
			if(counter[i][j]==3)
				max[i]=j;
		}
		printf("\n");
		printf("--------------------------------------------------\n");
	}
	printf("\n\n(3)\n\n     Position of counters from J1 to J8: \n\n");
	printf("--------------------------------------------------\n");
	for(i=0;i<8;i++){
		printf("%d ",max[i]);
		digit_2_6bits ( i, max[i] ,J );
	}
	printf("\n--------------------------------------------------\n");
	printf("\n");
	
//////////////////////////////////做J-->K
	for(i=0;i<=56;i++)
	{
		P1[i]=2;
	}
	for(i=0;i<=65;i++)
	{
		K[i]=2;
	}
	K[0]=3;					//避免當成未知
	for(i=1;i<=48;i++)
	{
		P1[ PC2[i] ] =J[i];
	}
	for(i=1;i<=56;i++)
	{
		K[ PC1_shift[i] ] = P1[i];
	}
	printf("\n\n(4)\n\n     The value of K   ( 56 bits )   :\n\n");
	printf("---------------------------------------------------------------------\n");
	for(i=1;i<=56;i++)
	{
		printf("%d",K[i] );
	}
	printf("\n\n");
	printf("where parity bits are omitted and \"2\" denotes an unknown key bit ");
	printf("\n---------------------------------------------------------------------\n\n\n");
//找出哪些位置是紀錄2 當成未知  紀錄在unknown[j]
	j=0;
	for(i=1;i<=64;i++)
	{
		if(K[i]==2 && i%8!=0)
		{
			unknown[j]=i;
			j++;
		}
	}
	printf("\n\n(5)\n\n     The result :\n\n");
	printf("---------------------------------------------------------------------\n");
// 暴力法測試
	int value,rem,k,m;
	for(m=0;m<=255;m++)
	{
		value=m;
			for(k=0;k<=7;k++)      //計算value內容 8 bits
			{
				rem = value%2;
				value=(int)value/2;
				Brute[7-k] = rem;
			}	
	//暴力的值 填入 未知的K位置
		for(i=0;i<=7;i++)
		{
			K[unknown[i]]=Brute[i];
		}
	//算出odd parity那位的0-1  將K填滿
		for(i=1;i<=8;i++)
		{
			int count=0;
			for(j=1;j<=7;j++)
			{
				if( K[ 8 * (i-1)+j ] == 1   )
				{
					count++;
				}
			}
			if(count%2==0)
				K[8*i]=1;
			else
				K[8*i]=0;
		}
	//測試是否K是正確的
		Real_key[16] = 0;
		k=runDES(plain1,cipher1,K);
		if(k==1)
		{
			//換算Real_key
			for(i=0;i<=15;i++)
			{
				int sum=0;
				for(j=1;j<=4;j++)
				{
					sum+=(int)pow(2,4-j)*K[i*4+j];

					switch (sum)      //sum決定Real_key[i]該為何
					{
						case 10:
							Real_key[i]='A';
							break;
						case 11:
							Real_key[i]='B';
							break;
						case 12:
							Real_key[i]='C';
							break;
						case 13:
							Real_key[i]='D';
							break;
						case 14:
							Real_key[i]='E';
							break;
						case 15:
							Real_key[i]='F';
							break;
						case 0:
							Real_key[i]='0';
							break;
						case 1:
							Real_key[i]='1';
							break;
						case 2:
							Real_key[i]='2';
							break;
						case 3:
							Real_key[i]='3';
							break;
						case 4:
							Real_key[i]='4';
							break;
						case 5:
							Real_key[i]='5';
							break;
						case 6:
							Real_key[i]='6';
							break;
						case 7:
							Real_key[i]='7';
							break;
						case 8:
							Real_key[i]='8';
							break;
						case 9:
							Real_key[i]='9';
							break;

					}
				}
			}
			printf("The complete KEY is: %s",Real_key);
			
		}
	}

	printf("\n");
	printf("---------------------------------------------------------------------\n");
	printf("\n\n");

}