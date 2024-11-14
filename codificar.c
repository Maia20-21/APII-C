#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

char *base64_encode(const unsigned char *input, int length) {
    BIO *bmem, *b64;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    char *buff = (char *)malloc(bptr->length + 1);
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = '\0';

    BIO_free_all(b64);

    return buff;
}

char *codificar_senha(const char *senha) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512((unsigned char *)senha, strlen(senha), hash);

    char *encoded = base64_encode(hash, SHA512_DIGEST_LENGTH);
    return encoded;
}

int main() {
    char senha[256];
    printf("# Digite as palavras da sua senha: ");
    fgets(senha, sizeof(senha), stdin);
    senha[strcspn(senha, "\n")] = '\0';

    char *codificada = codificar_senha(senha);
    printf("\n# Senha codificada: %s\n", codificada);

    free(codificada);
    return 0;
}

// gcc codificar.c -o codificar -lssl -lcrypto