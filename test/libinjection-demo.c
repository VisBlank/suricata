#include <stdio.h>
#include <libinjection.h>
int main(int argc, char *argv[]) {
    const char *ver = libinjection_version();
    printf("libinjection version: %s\n", ver); 

    if (argc != 3) {
        printf("libinjection-demo [sql|xss] [str]\n");
        return 0;
    }

    char fingerprint[128] = {0};
    if (strncmp("sql", argv[1], 3) == 0) {
        int ret = libinjection_sqli(argv[2], strlen(argv[2]), fingerprint);
        if (ret == 0)
            printf("benign\n");
        else
            printf("sqli\n");
    }

    return 0;
}
