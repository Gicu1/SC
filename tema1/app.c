#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define KEY_LENGTH 4

/* --- Cifrul de substituție --- */

/* Hartile predefinite pentru litere (majuscule și minuscule). */
const char *sub_enc_upper = "QWERTYUIOPASDFGHJKLZXCVBNM";
const char *sub_enc_lower = "qwertyuiopasdfghjklzxcvbnm";

char substitution_encrypt_char(char c)
{
    if (c >= 'A' && c <= 'Z')
    {
        return sub_enc_upper[c - 'A'];
    }
    else if (c >= 'a' && c <= 'z')
    {
        return sub_enc_lower[c - 'a'];
    }
    else
    {
        // caracterele care nu sunt litere rămân neschimbate
        return c;
    }
}

char substitution_decrypt_char(char c)
{
    if (c >= 'A' && c <= 'Z')
    {
        for (int i = 0; i < 26; i++)
        {
            if (sub_enc_upper[i] == c)
                return 'A' + i;
        }
    }
    else if (c >= 'a' && c <= 'z')
    {
        for (int i = 0; i < 26; i++)
        {
            if (sub_enc_lower[i] == c)
                return 'a' + i;
        }
    }
    return c;
}

void substitution_encrypt(const char *input, char *output)
{
    int i = 0;
    while (input[i] != '\0')
    {
        output[i] = substitution_encrypt_char(input[i]);
        i++;
    }
    output[i] = '\0';
}

void substitution_decrypt(const char *input, char *output)
{
    int i = 0;
    while (input[i] != '\0')
    {
        output[i] = substitution_decrypt_char(input[i]);
        i++;
    }
    output[i] = '\0';
}

/* --- Cifrul de transpunere (columnar) --- */

/*
   Algoritmul folosește o cheie predefinită de lungime 4.
   Se completează matricea cu caracterele din textul de intrare,
   iar dacă lungimea nu este multiplu de 4, celulele libere se umplu cu caracterul '_'.

   Pentru criptare:
   - Se definește o permutare a coloanelor {1, 3, 2, 0}.
   - Se citește matricea coloană cu coloană, în ordinea {1, 3, 2, 0}.

   Pentru decriptare:
   - Se inversează procesul: se completează matricea coloană cu coloană,
     apoi se citește rând cu rând.
*/

void transposition_encrypt(const char *input, char *output)
{
    int len = strlen(input);
    int rows = (len + KEY_LENGTH - 1) / KEY_LENGTH;
    int total = rows * KEY_LENGTH;
    char *matrix = (char *)malloc(total * sizeof(char));
    // Umple matricea rând cu rând; completează cu '_' dacă este necesar.
    for (int i = 0; i < total; i++)
    {
        if (i < len)
            matrix[i] = input[i];
        else
            matrix[i] = '_';
    }

    // Cheia predefinită și ordinea:
    int order[KEY_LENGTH] = {1, 3, 2, 0};

    int pos = 0;
    for (int i = 0; i < KEY_LENGTH; i++)
    {
        int col = order[i];
        for (int r = 0; r < rows; r++)
        {
            output[pos++] = matrix[r * KEY_LENGTH + col];
        }
    }
    output[pos] = '\0';
    free(matrix);
}

void transposition_decrypt(const char *input, char *output)
{
    int len = strlen(input);
    int rows = len / KEY_LENGTH; // Ar trebui să fie exact, deoarece am completat la criptare.
    int total = rows * KEY_LENGTH;
    char *matrix = (char *)malloc(total * sizeof(char));
    int order[KEY_LENGTH] = {1, 3, 2, 0};

    int pos = 0;
    // Completează matricea coloană cu coloană, conform ordinii de criptare.
    for (int i = 0; i < KEY_LENGTH; i++)
    {
        int col = order[i];
        for (int r = 0; r < rows; r++)
        {
            matrix[r * KEY_LENGTH + col] = input[pos++];
        }
    }
    // Se citește matricea rând cu rând.
    pos = 0;
    for (int i = 0; i < total; i++)
    {
        output[pos++] = matrix[i];
    }
    output[pos] = '\0';
    free(matrix);
}

/* ===== Funcția main și parsarea argumentelor ===== */

int main(int argc, char *argv[])
{
    if (argc < 5)
    {
        fprintf(stderr, "Utilizare: %s -e|-d <fisier_intrare> -o <fisier_iesire> [-alg sub|trans]\n", argv[0]);
        return 1;
    }
    int encrypt_mode = -1; // 1 pentru criptare, 0 pentru decriptare
    char *input_filename = NULL;
    char *output_filename = NULL;
    int use_substitution = 1; // 1 pentru substituție, 0 pentru transpunere

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-e") == 0)
        {
            encrypt_mode = 1;
            if (i + 1 < argc)
            {
                input_filename = argv[i + 1];
                i++;
            }
            else
            {
                fprintf(stderr, "Fisierul de intrare nu a fost specificat\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "-d") == 0)
        {
            encrypt_mode = 0;
            if (i + 1 < argc)
            {
                input_filename = argv[i + 1];
                i++;
            }
            else
            {
                fprintf(stderr, "Fisierul de intrare nu a fost specificat\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "-o") == 0)
        {
            if (i + 1 < argc)
            {
                output_filename = argv[i + 1];
                i++;
            }
            else
            {
                fprintf(stderr, "Fisierul de iesire nu a fost specificat\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "-alg") == 0)
        {
            if (i + 1 < argc)
            {
                if (strcmp(argv[i + 1], "sub") == 0)
                    use_substitution = 1;
                else if (strcmp(argv[i + 1], "trans") == 0)
                    use_substitution = 0;
                else
                {
                    fprintf(stderr, "Algoritm necunoscut. Se folosește 'sub' sau 'trans'.\n");
                    return 1;
                }
                i++;
            }
            else
            {
                fprintf(stderr, "Algoritmul nu a fost specificat\n");
                return 1;
            }
        }
    }
    if (encrypt_mode == -1 || input_filename == NULL || output_filename == NULL)
    {
        fprintf(stderr, "Utilizare: %s -e|-d <fisier_intrare> -o <fisier_iesire> [-alg sub|trans]\n", argv[0]);
        return 1;
    }

    // Citirea fișierului de intrare
    FILE *fin = fopen(input_filename, "r");
    if (fin == NULL)
    {
        fprintf(stderr, "Eroare la deschiderea fisierului de intrare: %s\n", input_filename);
        return 1;
    }
    fseek(fin, 0, SEEK_END);
    long fsize = ftell(fin);
    fseek(fin, 0, SEEK_SET);
    char *input_text = (char *)malloc(fsize + 1);
    size_t read_size = fread(input_text, 1, fsize, fin);
    input_text[read_size] = '\0';
    fclose(fin);

    // Alocare buffer pentru ieșire
    char *output_text = (char *)malloc(fsize * 4 + 1); // Asigurăm spațiu suficient

    // Apelarea funcției corespunzătoare
    if (use_substitution)
    {
        if (encrypt_mode)
        {
            substitution_encrypt(input_text, output_text);
        }
        else
        {
            substitution_decrypt(input_text, output_text);
        }
    }
    else
    { // cifru de transpunere
        if (encrypt_mode)
        {
            transposition_encrypt(input_text, output_text);
        }
        else
        {
            transposition_decrypt(input_text, output_text);
        }
    }

    // Scrierea rezultatului în fișierul de ieșire
    FILE *fout = fopen(output_filename, "w");
    if (fout == NULL)
    {
        fprintf(stderr, "Eroare la deschiderea fisierului de iesire: %s\n", output_filename);
        free(input_text);
        free(output_text);
        return 1;
    }
    fputs(output_text, fout);
    fclose(fout);

    free(input_text);
    free(output_text);
    return 0;
}
