#define LTM_DESC
#include <tomcrypt.h>

static unsigned char pt[17] = {""};//明文数据块
static int padding = 3;//填充方式
int err;//错误记录

int RSA(int padding)
{
	int hash_idx;
	int prng_idx;
	int res;
	unsigned long l1, l2;
	unsigned char ct[17] = {""}, out[1024] = {""};
	rsa_key key;
	FILE *filepwd= 0;

	//注册伪随机数生成器
	if (register_prng(&sprng_desc) == -1)
	{
		printf("伪随机数生成错误！");
		return EXIT_FAILURE;
	}

	ltc_mp = ltm_desc;

	//注册数学库
	if (register_hash(&sha1_desc) == -1)
	{
		printf("注册数学库失败！");
		return EXIT_FAILURE;
	}

	//在hash表里查找hash
	hash_idx = find_hash("sha1");

	//在prng表里查找prng
	prng_idx = find_prng("sprng");

	/*make an RSA-1024 key*/

	err = rsa_make_key(NULL,prng_idx,1024 / 8,65537,&key);
	if (err != CRYPT_OK)
	{
		printf("rsa make_key %s", error_to_string(err));
		return EXIT_FAILURE;
	}

	printf("加密操作：\n");
	l1 = sizeof(out);

	//加密操作
	err = rsa_encrypt_key_ex(pt,16,out,&l1,(unsigned char *)"lcy",16,NULL,prng_idx,hash_idx,padding,&key);
		
	if (err != CRYPT_OK)
	{
		printf("rsa_encrpty_key %s", error_to_string(err));
		return EXIT_FAILURE;
	}

	//打开密文文件
	filepwd = fopen("D:\\Visual Studio code\\code\\RSA\\pwd.txt", "wb");
	if (filepwd == 0) {
		printf("can't open file");
		fclose(filepwd);
		return EXIT_FAILURE;
	}

	printf("输出密文：\n");
	for (int i = 0; i <= 127; i++)
	{
		printf("%02x", out[i]);
	}
	printf("\n");
	
	//将加密后的密文写入文件pwd中
	fwrite(out, sizeof(out[0]), l1, filepwd);
	printf("已成功将密文写入文件\n");

	fclose(filepwd);


	printf("解密操作：\n");
	l2 = sizeof(ct);


	//打开密文文件
	filepwd = fopen("D:\\Visual Studio code\\code\\RSA\\pwd.txt", "rb");
	if (filepwd == 0) {
		printf("can't open file");
		fclose(filepwd);
		return EXIT_FAILURE;
	}

	memset(out, 0, sizeof(out));
	while(!feof(filepwd)) {
		int len = fread(out, sizeof(out[0]), 128, filepwd);
		if (len < 1)//没有读成功
			break;
	}

	fclose(filepwd);

	//解密操作
	err = rsa_decrypt_key_ex(out,l1,ct,&l2,(unsigned char *)"lcy",16,hash_idx,padding,&res,&key);
	if (err!= CRYPT_OK)
	{
		printf("rsa_encrypt_key %s", error_to_string(err));
		return EXIT_FAILURE;
	}

	printf("输出明文：%s\n", ct);
}

int main(int argc, char* argv[])
{
	while (true)
	{
		int padding;
		memset(pt, 0, sizeof(pt));
		printf("请输入口令：\n");
		scanf("%s", &pt);
		printf("请选择填充方式:\n1.LTC_PKCS_1_V1_5\n2.LTC_PKCS_1_OAEP\n3.退出操作\n");
		scanf_s("%d", &padding);//读取填充方式
		switch (padding)
		{
		case 1:
			//填充方式LTC_LTC_PKCS_1_V1_5
			padding = LTC_LTC_PKCS_1_V1_5;
			break;

		case 2:
			//填充方式LTC_LTC_PKCS_1_OAEP
			padding = LTC_LTC_PKCS_1_OAEP;
			break;

		case 3:
			return 0; //退出操作
		}
		RSA(padding);
	}
}
