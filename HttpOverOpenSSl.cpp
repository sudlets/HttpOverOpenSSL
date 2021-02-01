// EducationOpenSSl.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.
//
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/buffer.h>
#include <openssl/x509v3.h>
#include <openssl/opensslconf.h>

#include <windows.h>
#include <wincrypt.h>
#include <tchar.h>
#pragma comment(lib, "Crypt32.lib")

#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")


#define HOST_NAME "example.com"
#define HOST_PORT "443"

//#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

void print_error_string(unsigned long err, const char* const label)
{
    const char* const str = ERR_reason_error_string(err);
    if (str)
        fprintf(stderr, "%s\n", str);
    else
        fprintf(stderr, "%s failed: %lu (0x%lx)\n", label, err, err);
}

void freememory(BIO* out, BIO* web, SSL_CTX* ctx, char* tmpbuf)
{
    if (out)
        BIO_free(out);

    if (web != NULL)
        BIO_free_all(web);

    if (NULL != ctx)
        SSL_CTX_free(ctx);

    delete[] tmpbuf;
}

int main()
{
    //SSL_load_error_strings(); // Устарела. С сверсии 1.1.0 вызывается неявно
    //ERR_load_BIO_strings(); // Устарела. С сверсии 1.1.0 вызывается неявно
    //OpenSSL_add_all_algorithms(); // Устарела. С сверсии 1.1.0 вызывается неявно

    BIO* web = nullptr; 
    BIO* out = nullptr;
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    int lenbuf = 4096;
    char *tmpbuf = new char[lenbuf];
    int len = 0;
    int iResult = 0;
    unsigned long ssl_err = 0;

    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    ssl_err = ERR_get_error();
    if (out == NULL)
    {
        freememory(out, web, ctx, tmpbuf);
        print_error_string(ssl_err, "BIO_new_fp");
        exit(1); /* failed */
    }

    // Фактическая используемая версия протокола будет согласована 
    // до самой высокой версии, взаимно поддерживаемой клиентом и сервером.
    ctx = SSL_CTX_new(TLS_client_method());
    ssl_err = ERR_get_error();
    if (ctx == NULL)
    {
        freememory(out, web, ctx, tmpbuf);
        print_error_string(ssl_err, "SSL_CTX_new");
        exit(1); /* failed */
    }

    //Функция устанавливают минимальную поддерживаемую версию протокола для ctx.
    iResult = SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    ssl_err = ERR_get_error();
    if (iResult == 0)
    {
        freememory(out, web, ctx, tmpbuf);
        print_error_string(ssl_err, "SSL_CTX_set_min_proto_version");
        exit(2); /* failed */
    }

    //--------------------------
    HCERTSTORE  hSystemStore;
    PCCERT_CONTEXT pCertContext = NULL;
    X509* x509;
    X509_STORE* store = X509_STORE_new();

    if (hSystemStore = CertOpenSystemStore(0, _T("ROOT")))
    {
        printf("The CA system store is open. Continue.\n");
    }
    else
    {
        printf("The CA system store did not open.\n");
        exit(1);
    }

    while (pCertContext = CertEnumCertificatesInStore(hSystemStore, pCertContext))
    {
        const unsigned char* encoded_cert = pCertContext->pbCertEncoded;
        x509 = NULL;
        x509 = d2i_X509(NULL, &encoded_cert, pCertContext->cbCertEncoded);
        if (x509)
        {
            int i = X509_STORE_add_cert(store, x509);

            if (i == 1)
                printf("certificate added\n");

            X509_free(x509);
        }
    }
    //--------------------------





    // указывает, что следует использовать местоположения по умолчанию, 
    // из которых загружаются сертификаты CA
    //iResult = SSL_CTX_load_verify_locations(ctx, "DigiCert.pem", NULL);
    //iResult = SSL_CTX_set_default_verify_paths(ctx);
    SSL_CTX_set_cert_store(ctx, store);
    //ssl_err = ERR_get_error();
    //if (iResult == 0)
    //{
    //    freememory(out, web, ctx, tmpbuf);
    //    print_error_string(ssl_err, "SSL_CTX_set_default_verify_paths");
    //    exit(3); /* failed */
    //}

    // Cоздает новую цепочку BIO, состоящую из SSL BIO (с использованием ctx ), 
    // за которым следует соединение BIO.
    web = BIO_new_ssl_connect(ctx);
    ssl_err = ERR_get_error();
    if (web == NULL)
    {
        freememory(out, web, ctx, tmpbuf);
        print_error_string(ssl_err, "BIO_new_ssl_connect");
        exit(4); /* failed */
    }

    // Bспользует строковое имя для установки имени хоста. 
    // Имя хоста может быть IP-адресом; если адрес IPv6, его необходимо 
    // заключить в квадратные скобки. Имя хоста также может включать порт 
    // в форме "имя_хоста:порт".
    iResult = BIO_set_conn_hostname(web, HOST_NAME ":" HOST_PORT);
    ssl_err = ERR_get_error();
    if (iResult == 0)
    {
        freememory(out, web, ctx, tmpbuf);
        print_error_string(ssl_err, "BIO_set_conn_hostname");
        exit(5); /* failed */
    }

    // Bзвлекает SSL-указатель из BIO (web) , после чего им можно управлять с 
    // помощью стандартных функций библиотеки SSL.
    BIO_get_ssl(web, &ssl);
    ssl_err = ERR_get_error();
    if (ssl == NULL) 
    {
        freememory(out, web, ctx, tmpbuf);
        print_error_string(ssl_err, "BIO_get_ssl");
        exit(6); /* failed */
    }

    /* Не хочу повторных попыток (см. документацию) */
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY); 

    // Использует расширение TLS SNI для установки имени хоста. 
    // Если вы подключаетесь к серверу, поддерживающему указание имени 
    // сервера (например, Apache с виртуальными хостами на основе имени или 
    // IIS 8.0), то во время рукопожатия вы получите соответствующий сертификат.
    iResult = SSL_set_tlsext_host_name(ssl, HOST_NAME);
    ssl_err = ERR_get_error();
    if (iResult != 1)
    {
        freememory(out, web, ctx, tmpbuf);
        print_error_string(ssl_err, "SSL_set_tlsext_host_name");
        exit(7); /* failed */
    }

    // Пытается подключить поставляемый BIO. Возвращает 1, если соединение 
    // было установлено успешно. 
    iResult = BIO_do_connect(web);
    ssl_err = ERR_get_error();
    if (iResult != 1)
    {
        freememory(out, web, ctx, tmpbuf);
        print_error_string(ssl_err, "BIO_do_connect");
        exit(8); /* failed */
        /*Если соединение не может быть установлено, возвращается нулевое 
        или отрицательное значение, для неблокирующих BIO соединений следует 
        использовать вызов BIO_should_retry (), чтобы определить, следует ли 
        повторить вызов.*/
    }

    // Пытается завершить квитирование SSL на предоставленном BIO и 
    // установить SSL-соединение. 
    iResult = BIO_do_handshake(web);
    ssl_err = ERR_get_error();
    if (iResult != 1)
    {
        freememory(out, web, ctx, tmpbuf);
        print_error_string(ssl_err, "BIO_do_handshake");
        exit(9); /* failed */
    }

    /*Проверка сертификата*/

    /* Шаг 1: убедитесь, что сертификат сервера был представлен во время переговоров */
    X509* cert = SSL_get_peer_certificate(ssl);
    if (cert) { X509_free(cert); } /* Освободить память */
    if (cert == NULL)
    {
        freememory(out, web, ctx, tmpbuf);
        print_error_string(X509_V_ERR_APPLICATION_VERIFICATION, "SSL_get_peer_certificate");
        exit(10); /* failed */
    }

    /* Шаг 2: проверка сертификата X509 */
    /* Проверка выполнена в соответствии с RFC 4158 */
    iResult = SSL_get_verify_result(ssl);
    switch (iResult)
    {
    case(X509_V_OK):
        break;
    case(X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN):
        printf("X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN\n\n");
        break;
    default:
        freememory(out, web, ctx, tmpbuf);
        print_error_string((unsigned long)iResult, "SSL_get_verify_results");
        exit(11); /* failed */
    }
   
    /* Step 3: hostname verifcation.   */
        /* An exercise left to the reader. */
    SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    iResult = SSL_set1_host(ssl, HOST_NAME);
    if (iResult == 0) 
    {
        freememory(out, web, ctx, tmpbuf);
        print_error_string(ssl_err, "SSL_set1_host");
        exit(12); /* failed */
    }

       // Управление режимом проверки сертификата
    // SSL_VERIFY_PEER: Если процесс проверки сертификата сервера
    // завершается неудачно, рукопожатие TLS / SSL немедленно завершается.
    // Функция не возвращает диагностическую информацию (void)
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);


    BIO_puts(web, "GET / HTTP/1.1\r\n"
        "Host: " HOST_NAME "\r\n"
        "Connection: close\r\n\r\n");

    BIO_puts(out, "\n");

    do
    {
        len = BIO_read(web, tmpbuf, lenbuf);

        if (len > 0)
            BIO_write(out, tmpbuf, len);

    } while (len > 0 || BIO_should_retry(web));

    /*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
    
    freememory(out, web, ctx, tmpbuf);

    if (!CertCloseStore(hSystemStore, 0))
    {
        printf("Unable to close the CA system store.\n");
        exit(1);
    }

    return 0;
}

/*
BIO* cbio, * out;
    int len;
    char tmpbuf[1024];

    cbio = BIO_new_connect("example.com:http");

    out = BIO_new_fp(stdout, BIO_NOCLOSE);

    if (BIO_do_connect(cbio) <= 0)
    {
        fprintf(stderr, "Error connecting to server\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    BIO_puts(cbio, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");

    for (;;)
    {
        len = BIO_read(cbio, tmpbuf, 1024);
        if (len <= 0)
            break;
        BIO_write(out, tmpbuf, len);
    }

    BIO_free(cbio);
    BIO_free(out);
*/


/*
SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();

    int errorssl = SSL_ERROR_SYSCALL;
    std::string text;
    BIO* web, *out;
    int len;
    char tmpbuf[4096];
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;

    ctx = SSL_CTX_new(TLS_client_method());
    ssl = SSL_new(ctx);

    web = BIO_new_ssl_connect(ctx);
    BIO_set_conn_hostname(web, "example.com:443");

    BIO_get_ssl(web, &ssl);
    //SSL_set0_rbio(ssl, web);
    //SSL_set0_wbio(ssl, web);

    //int iResult = SSL_connect(ssl);



    //BIO_get_ssl(web, &ssl);

    //cbio = BIO_new_connect("example.com:http");

    out = BIO_new_fp(stdout, BIO_NOCLOSE);

    /*if (BIO_do_connect(cbio) <= 0)
    {
        fprintf(stderr, "Error connecting to server\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

SSL_write(ssl, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", 38);
//BIO_puts(cbio, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");

for (;;)
{
    len = SSL_read(ssl, tmpbuf, 4096);
    if (len <= 0)
    {
        errorssl = SSL_get_error(ssl, len);
        break;
    }

    BIO_write(out, tmpbuf, len);
}

int closeconnect = SSL_shutdown(ssl);

if (closeconnect == 0)
{
    do
    {
        char c;
        SSL_read(ssl, &c, 1);
        closeconnect = SSL_get_shutdown(ssl);
    } while (closeconnect != SSL_RECEIVED_SHUTDOWN);
}
/*while (len = SSL_read(ssl, tmpbuf, 4096) > 0)
{
    BIO_write(out, tmpbuf, len);
};

BIO_free_all(out);
BIO_free_all(web);
//SSL_free(ssl);
SSL_CTX_free(ctx);
*/