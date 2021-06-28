// GRR20163049 Bruno Henrique Labres
// GRR20171588 Eduardo Henrique Trevisan

#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>

void printBN(char*msg, BIGNUM*a){// Convert the BIGNUM to number string
	char*number_str = BN_bn2hex(a);
	// Print out the number string
	printf("%s %s\n", msg, number_str);
	// Free the dynamically allocated memory
	OPENSSL_free(number_str);
}

int main(){
	BN_CTX*ctx = BN_CTX_new();
	BIGNUM*p = BN_new();
	BIGNUM*q = BN_new();
	BIGNUM*e = BN_new();
	BIGNUM*n = BN_new();
	BIGNUM*um = BN_new();
	BIGNUM*d = BN_new();
	BIGNUM*M2 = BN_new();
	BIGNUM*M = BN_new();
	BIGNUM*cifrado = BN_new();
	BIGNUM*decifrado = BN_new();
	BIGNUM*assinado2 = BN_new();
	BIGNUM*res = BN_new();
	BIGNUM*gcd = BN_new();
	BIGNUM*tot = BN_new();
	BIGNUM*rem = BN_new();
	BIGNUM*plain = BN_new();
	BIGNUM*assinado = BN_new();
	
	BIGNUM*p_menosum = BN_new();
	BIGNUM*q_menosum = BN_new();

	char *msg = "BN: ";

	// task 1 /////////////////////////////////////////////////////////////////////////
	puts("Task 1:");
	BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
	BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
	BN_hex2bn(&e, "0D88C3");
	BN_hex2bn(&um, "1");

	// obter a chave privada
	BN_sub(p_menosum, p, um);
	BN_sub(q_menosum, q, um);

	// calculo do totiente
	BN_mul(n, p, q, ctx);
	BN_mul(res, p_menosum, q_menosum, ctx);
	BN_gcd(gcd, p_menosum, q_menosum, ctx);
	// a lib nao calcula mmc, entao utilizamos essao equacao para calcular a partir do mdc
	BN_div(tot, rem, res, gcd, ctx); // conseguir mmc
	// BN_mul(res, p, q, ctx);

	
	msg = "BN: ";
	printBN(msg, tot);

	// calcular expoente d da chave privada
	BN_mod_inverse(d, e, tot, ctx);
	msg = "chave publica: ";
	printBN(msg, e);
	printBN(msg, n);

	msg = "chave privada: ";
	printBN(msg, d);
	printBN(msg, n);
	BN_hex2bn(&M, "4120746f702073656372657421");


	BN_mod_exp(cifrado, M, e, n, ctx);
	msg = "cifrado t1: ";
	printBN(msg, cifrado);
	BN_mod_exp(decifrado, cifrado, d, n, ctx);
	msg = "decifrado t1: ";
	printBN(msg, decifrado);

	// task 2 //////////////////////////////////////////////////////////////////////
	puts("\nTask 2:");

	// cifrando
	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	BN_hex2bn(&e, "010001");
	BN_hex2bn(&M, "4120746f702073656372657421");
	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

	BN_mod_exp(cifrado, M, e, n, ctx);
	msg = "cifrado t2: ";
	printBN(msg, cifrado);

	//decifrando
	BN_mod_exp(decifrado, cifrado, d, n, ctx);
	msg = "decifrado t2: ";
	printBN(msg, decifrado);


	// task 3 /////////////////////////////////////////////////////////////////////////
	puts("\nTask 3:");

	BN_hex2bn(&cifrado, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");
	BN_mod_exp(decifrado, cifrado, d, n, ctx);
	msg = "decifrado t3: ";
	printBN(msg, decifrado);

	// task 4 /////////////////////////////////////////////////////////////////////////
	puts("\nTask 4:");

	BN_hex2bn(&M, "49206f776520796f752024323030302e");	// 2000
	BN_hex2bn(&M2, "49206f776520796f752024333030302e"); // 3000
	BN_mod_exp(assinado, M, d, n, ctx);
	BN_mod_exp(assinado2, M2, d, n, ctx);
	msg = "assinado t4: ";
	printBN(msg, assinado);
	printBN(msg, assinado2);

	// task 5 /////////////////////////////////////////////////////////////////////////
	puts("\nTask 5:");

	BN_hex2bn(&M, "4c61756e63682061206d6973736c652e");
	BN_hex2bn(&assinado, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
	BN_hex2bn(&e, "010001");
	BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");

	BN_mod_exp(decifrado, assinado, e, n, ctx);
	printBN("mensagem original:",M);
	printBN("mensagem decifrada:",decifrado);
	BN_hex2bn(&assinado, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
	BN_mod_exp(decifrado, assinado, e, n, ctx);
	printBN("mensagem decifrada com assinatura adulterada:",decifrado);
}