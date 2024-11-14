#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "json.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <cifuzz/cifuzz.h>

// Function to test setting JSON pointers
void test_example_set(FuzzedDataProvider &fdp) {
    struct json_object *jo1 = json_tokener_parse(fdp.ConsumeRandomLengthString(1024).c_str());
    if (jo1 == NULL) return;

    struct json_object *jo2 = NULL;
    if (fdp.ConsumeBool()) {
        jo2 = json_tokener_parse(fdp.ConsumeRandomLengthString(1024).c_str());
    }

    const char *json_pointer = fdp.ConsumeRandomLengthString(256).c_str();
    struct json_object *new_obj = NULL;
    switch (fdp.ConsumeIntegralInRange<int>(0, 3)) {
        case 0:
            new_obj = json_object_new_string(fdp.ConsumeRandomLengthString(256).c_str());
            break;
        case 1:
            new_obj = json_object_new_int(fdp.ConsumeIntegral<int>());
            break;
        case 2:
            new_obj = json_object_new_object();
            break;
        case 3:
            new_obj = json_object_new_array();
            break;
    }

    json_pointer_set(&jo1, json_pointer, new_obj);
    json_pointer_setf(&jo1, new_obj, "%s%s/%d", fdp.ConsumeRandomLengthString(128).c_str(), fdp.ConsumeRandomLengthString(128).c_str(), fdp.ConsumeIntegral<int>());

    json_object_put(jo1);
    if (jo2 != NULL) {
        json_object_put(jo2);
    }
}

FUZZ_TEST_SETUP() {
    // One-time initialization tasks, if any
}

FUZZ_TEST(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    test_example_set(fdp);
}
