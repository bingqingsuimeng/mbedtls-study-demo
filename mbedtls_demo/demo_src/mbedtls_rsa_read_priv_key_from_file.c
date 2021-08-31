#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf       printf
#define mbedtls_exit         exit
#define MBEDTLS_EXIT_SUCCESS EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */


#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/pk.h"
#include <stdio.h>
#include <string.h>

int rsa_encrypt()
{
    FILE* f = NULL;
    long size;
    size_t n;
    unsigned char* publickey = NULL;
    mbedtls_pk_context ctx_pk;

/*********************************************/
    int ret = 1;

    size_t i;
    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char input[1024];
    unsigned char buf[512];
    const char* pers = "rsa_encrypt";
    mbedtls_mpi N, E;       //定义一个大数，也就是公钥
/*****************************************************/
    mbedtls_pk_init(&ctx_pk);

    if ((f = fopen("rsa4096_pub.pem", "rb")) == NULL)      //打开pem格式的公钥文件
    {
        mbedtls_printf("\n  .  Open public key file failed!");
        return(-1);
    }
    fseek(f, 0, SEEK_END);
    if ((size = ftell(f)) == -1)
    {
        fclose(f);
        return(-1);
    }
    fseek(f, 0, SEEK_SET);

    n = (size_t)size;    //

    if (n + 1 == 0 || (publickey = mbedtls_calloc(1, n + 1)) == NULL)
    {
        fclose(f);
        return(-1);
    }

    if (fread(publickey, 1, n, f) != n)
    {
        fclose(f);
        free(publickey);
        publickey = NULL;
        return(-1);
    }
    fclose(f);

    /*从pem文件里获得公钥*/
    if (0 != mbedtls_pk_parse_public_key(&ctx_pk, publickey, n + 1))
    {
        mbedtls_printf("\n  . Can't import public key");
    }
    else
    {
        mbedtls_printf("\n  . Import public key successfully");
    }

    free(publickey);
    publickey = NULL;
    /*****************************************************************/

    mbedtls_printf("\n  . Seeding the random number generator...");

    memset(input, 0, 1024);
    fflush(stdout);

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&E);
    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
    mbedtls_ctr_drbg_init(&ctr_drbg);      //初始化ctr drbg结构体,用于随机数的生成
    mbedtls_entropy_init(&entropy);       //初始化熵源

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers));     //生成随机数

    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }
    /*导入pem内的公钥*/
    rsa = *(mbedtls_rsa_context*)ctx_pk.pk_ctx;      

    input[0] = 'H';
    input[1] = 'E';
    input[2] = 'L';
    input[3] = 'L';
    input[4] = 'O';
    input[5] = ',';
    input[6] = 'W';
    input[7] = 'O';
    input[8] = 'R';
    input[9] = 'L';
    input[10] = 'D';
    input[11] = '!';
    input[12] = '\0';

    /*
     * Calculate the RSA encryption of the hash.
     */
    mbedtls_printf("\n  . Generating the RSA encrypted value");
    fflush(stdout);
    /*加密操作，利用公钥加密*/
    ret = mbedtls_rsa_pkcs1_encrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC, 12, input, buf);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_pkcs1_encrypt returned %d\n\n", ret);
        goto exit;
    }

    /*
     * Write the signature into result-enc.txt
     */
    if ((f = fopen("result-enc.txt", "wb+")) == NULL)      //将加密文件写入到result-enc.txt
    {
        mbedtls_printf(" failed\n  ! Could not create %s\n\n", "result-enc.txt");
        goto exit;
    }

    for (i = 0; i < rsa.len; i++)
    {
        mbedtls_fprintf(f, "%02X%s", buf[i], (i + 1) % 16 == 0 ? "\r\n" : " ");
    }
    fclose(f);

    mbedtls_printf("\n  . Done (created "%s")\n\n", "result-enc.txt");  

exit:
    /*释放资源*/
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&E);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_rsa_free(&rsa);
    return 0;
}

int rsa_decrypt()
{
    FILE* f = NULL;
    long size;
    size_t n;
    unsigned char* privatekey = NULL;
    mbedtls_pk_context ctx_pk;
    /*******************************/
    int ret = 1;
    int c;
    size_t i;
    mbedtls_rsa_context rsa;
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;      //定义大数
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char result[1024];
    unsigned char buf[512];
    const char* pers = "rsa_decrypt";
    memset(result, 0, sizeof(result));
    /*********************************/
    mbedtls_pk_init(&ctx_pk);
   
    if ((f = fopen("rsa4096_prv.pem", "rb")) == NULL)      //打开pem格式的公钥文件
    {
        mbedtls_printf("\n  . Open private key file failed!");
        return(-1);
    }

    fseek(f, 0, SEEK_END);

    if ((size = ftell(f)) == -1)
    {
        fclose(f);
        return(-1);
    }
    fseek(f, 0, SEEK_SET);

    n = (size_t)size;    //

    if (n + 1 == 0 || (privatekey = mbedtls_calloc(1, n + 1)) == NULL)
    {
        fclose(f);
        return(-1);
    }

    if (fread(privatekey, 1, n, f) != n)
    {
        fclose(f);
        free(privatekey);
        privatekey = NULL;
        return(-1);
    }
    fclose(f);

    /*从pem文件里获得私钥*/
    if (0 != mbedtls_pk_parse_key(&ctx_pk, privatekey, n + 1, NULL, 0))
    {
        mbedtls_printf("\n  . Can't import private key");
    }
    else
    {
        mbedtls_printf("\n  . Import private key successfully");
    }

    free(privatekey);
    privatekey = NULL;

    mbedtls_printf("\n  . Seeding the random number generator...");
    fflush(stdout);

    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D);
    mbedtls_mpi_init(&E);
    mbedtls_mpi_init(&DP);
    mbedtls_mpi_init(&DQ);
    mbedtls_mpi_init(&QP);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
        &entropy, (const unsigned char*)pers,
        strlen(pers));
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n",
            ret);
        goto exit;
    }

    /*导入pem内的私钥*/
    rsa = *(mbedtls_rsa_context*)ctx_pk.pk_ctx;

    if ((ret = mbedtls_rsa_complete(&rsa)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_complete returned %d\n\n", ret);
        goto exit;
    }

    /*
     * Extract the RSA encrypted value from the text file
     */
    if ((f = fopen("result-enc.txt", "rb")) == NULL)
    {
        mbedtls_printf("\n  ! Could not open %s\n\n", "result-enc.txt");
        goto exit;
    }

    i = 0;

    while (fscanf(f, "%02X", &c) > 0 && i < (int)sizeof(buf))
        buf[i++] = (unsigned char)c;

    fclose(f);

    if (i != rsa.len)
    {
        mbedtls_printf("\n  ! Invalid RSA signature format\n\n");
        goto exit;
    }

    /*
     * Decrypt the encrypted RSA data and print the result.
     */
    mbedtls_printf("\n  . Decrypting the encrypted data");
    fflush(stdout);

    ret = mbedtls_rsa_pkcs1_decrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, &i, buf, result, 1024);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_pkcs1_decrypt returned %d\n\n", ret);      
        goto exit;
    }

    mbedtls_printf("\n  . OK\n\n");

    mbedtls_printf("The decrypted result is: '%s'\n\n", result);

exit:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_rsa_free(&rsa);
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&E);
    mbedtls_mpi_free(&DP);
    mbedtls_mpi_free(&DQ);
    mbedtls_mpi_free(&QP);

    return 0;


}
int main()
{
    int exit_code = 0;
    rsa_encrypt();     //加密
    rsa_decrypt();     //解密

#if defined(_WIN32)
    mbedtls_printf("  + Press Enter to exit this program.\n");
    fflush(stdout);
    getchar();
#endif

    return(exit_code);
}
