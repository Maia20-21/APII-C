#include <stdio.h>
#include <stdlib.h>

#define MAX_PALAVRAS 10000
#define MAX_TAM_PALAVRA 100

// Função para pegar uma palavra do arquivo
char* pegar_palavra(FILE *arquivo, char palavra[]) {
    
    if (fscanf(arquivo, "%s", palavra) == 1){
    return palavra;
  }
  else {return NULL;}
}


// Função para gerar as combinações
void gerar_combinacoes(char palavras[MAX_PALAVRAS][MAX_TAM_PALAVRA], int num_palavras) {
    FILE *saida = fopen("lista.txt", "a");
    if (!saida) {
        fprintf(stderr, "Erro ao abrir o arquivo de saída.\n");
        return;
    }

    // Gerando combinações
    for (int i = 0; i < num_palavras; i++) {
        fprintf(saida, "%s\n", palavras[i]); // 1 palavra

        for (int j = 0; j < num_palavras; j++) {
            fprintf(saida, "%s %s\n", palavras[i], palavras[j]); // 2 palavras

            for (int k = 0; k < num_palavras; k++) {
                fprintf(saida, "%s %s %s\n", palavras[i], palavras[j], palavras[k]); // 3 palavras

                for (int l = 0; l < num_palavras; l++) {
                    fprintf(saida, "%s %s %s %s\n", palavras[i], palavras[j], palavras[k], palavras[l]); // 4 palavras

                    for (int m = 0; m < num_palavras; m++) {
                        fprintf(saida, "%s %s %s %s %s\n", palavras[i], palavras[j], palavras[k], palavras[l], palavras[m]); // 5 palavras
                    }
                }
            }
        }
    }

    fclose(saida);
}

// Função para ler o arquivo de palavras e armazená-las em um array
int ler_palavras(char palavras[MAX_PALAVRAS][MAX_TAM_PALAVRA]) {
    
    FILE *saida = fopen("palavra.txt", "r");
    if (!saida) {
        fprintf(stderr, "Erro ao abrir o arquivo de saída.\n");
        return 1;
    }

    int i = 0;
    char palavra[MAX_TAM_PALAVRA];
    while (pegar_palavra(saida, palavra)) {
        // Copia a palavra lida para o array de palavras, caractere por caractere
        int j = 0;
        while (palavra[j] != '\0' && j < MAX_TAM_PALAVRA - 1) {
            palavras[i][j] = palavra[j];
            //printf("%s", palavras[i]);
            //printf("\n");
            j++;
        }
        palavras[i][j] = '\0'; // Garantir a terminação nula
        i++;
        if (i >= MAX_PALAVRAS) break; // Limite máximo de palavras
    }
    fclose(saida);
    if (i == 0) {
        fprintf(stderr, "Nenhuma palavra foi lida do arquivo.\n");
    }

    return i; // Retorna o número de palavras lidas
}

int main() {
    char palavras[MAX_PALAVRAS][MAX_TAM_PALAVRA];
    int num_palavras = ler_palavras(palavras);
    printf("%d\n", num_palavras);
    num_palavras = 1;

    if (num_palavras > 0) {
        gerar_combinacoes(palavras, num_palavras);
    } else {
        printf("Nenhuma palavra foi lida do arquivo.\n");
    }

    return 0;
}