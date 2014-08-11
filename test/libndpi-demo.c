#include <ndpi_main.h>
static void test_3rd_party_lib(void) {
    const char *ndpi_rev = ndpi_revision();
    printf("libndpi revison %s\n", ndpi_rev);
}

int main() {
	test_3rd_party_lib();
	return 0;
}
