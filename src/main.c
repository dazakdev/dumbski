#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdlib.h>
#include <openssl/sha.h>

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

    SHA_CTX shaContext;
    SHA1_Init(&shaContext);

    unsigned char buffer[BUFFER_SIZE];
    size_t bytesRead;

    // Czytanie pliku kawałek po kawałku
    while ((bytesRead = fread(buffer, 1, BUFFER_SIZE, file))) {
        SHA1_Update(&shaContext, buffer, bytesRead);
    }

    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1_Final(hash, &shaContext);
    fclose(file);

    // Konwersja na format hex
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(&output_hex[i * 2], "%02x", hash[i]);
    }
    output_hex[SHA_DIGEST_LENGTH * 2] = '\0';

    return 0;
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

    char *content = getFileContent(found_path);
    if (content) {
        printf("File content:\n%s\n", content);
        free(content);
    }

    char sha1_hash[SHA_DIGEST_LENGTH * 2 + 1];
    if (calculate_file_sha1(found_path, sha1_hash) == 0) {
        printf("%s  %s\n", sha1_hash, found_path);
    } else {
        printf("Failed to calculate SHA1 hash.\n");
    }

    return 0;
}