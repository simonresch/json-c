#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "json.h"
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>

// Function to test json_pointer_get with recursion
static void test_recursion_get(const char *json_str) {
    struct json_object *jo2, *jo1 = json_tokener_parse(json_str);

    jo2 = NULL;
    if (jo1 != NULL) {
        json_pointer_get(jo1, "/arr/0/obj/2/obj1", &jo2);
        json_pointer_get(jo1, "/arr/0/obj/2/obj2", &jo2);
        json_pointer_getf(jo1, &jo2, "/%s/%d/%s/%d/%s", "arr", 0, "obj", 2, "obj2");
        json_pointer_get(jo1, "/obj/obj/obj/0/obj1", &jo2);
        json_pointer_get(jo1, "/obj/obj/obj/0/obj2", &jo2);
        json_pointer_getf(jo1, &jo2, "%s", "\0");
        json_object_put(jo1);
    }
}

// Fuzzing entry point
FUZZ_TEST(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Consume a string from the fuzzer data
    std::string json_str = fdp.ConsumeRandomLengthString(1024);

    // Call the test function with the fuzzed string
    test_recursion_get(json_str.c_str());
}
