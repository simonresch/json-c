#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "json.h"

// Function to test array insertions
void test_array_insert_idx(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    json_object *my_array = json_object_new_array();
    json_object_array_add(my_array, json_object_new_int(fdp.ConsumeIntegral<int>()));
    json_object_array_add(my_array, json_object_new_int(fdp.ConsumeIntegral<int>()));
    json_object_array_add(my_array, json_object_new_int(fdp.ConsumeIntegral<int>()));

    json_object_array_insert_idx(my_array, 2, json_object_new_int(fdp.ConsumeIntegral<int>()));
    json_object *jo1 = json_tokener_parse("[1, 2, 4, 5]");
    if (jo1 != NULL) {
        if (json_object_equal(my_array, jo1)) {
            json_object_put(jo1);
            json_object_array_insert_idx(my_array, 2, json_object_new_int(fdp.ConsumeIntegral<int>()));
            jo1 = json_tokener_parse("[1, 2, 3, 4, 5]");
            if (jo1 != NULL) {
                if (json_object_equal(my_array, jo1)) {
                    json_object_put(jo1);
                    json_object_array_insert_idx(my_array, 5, json_object_new_int(fdp.ConsumeIntegral<int>()));
                    jo1 = json_tokener_parse("[1, 2, 3, 4, 5, 6]");
                    if (jo1 != NULL) {
                        if (json_object_equal(my_array, jo1)) {
                            json_object_put(jo1);
                            json_object_array_insert_idx(my_array, 7, json_object_new_int(fdp.ConsumeIntegral<int>()));
                            jo1 = json_tokener_parse("[1, 2, 3, 4, 5, 6, null, 8]");
                            if (jo1 != NULL) {
                                json_object_equal(my_array, jo1);
                                json_object_put(jo1);
                            }
                        } else {
                            json_object_put(jo1);
                        }
                    }
                } else {
                    json_object_put(jo1);
                }
            }
        } else {
            json_object_put(jo1);
        }
    }

    json_object_put(my_array);
}

// Fuzz test entry point
FUZZ_TEST(const uint8_t *data, size_t size) {
    test_array_insert_idx(data, size);
}
