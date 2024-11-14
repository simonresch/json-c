#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <json.h>
#include <json_tokener.h>
#include <json_util.h>
#include <json_object.h>
#include <json_object_private.h>
#include <json_visit.h>
#include <json_pointer.h>
#include <json_object_iterator.h>
#include <printbuf.h>
#include <locale.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <strings.h>
#include <json_inttypes.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

// This function will be used in the fuzz test
static void test_array_insert_idx(void) {
    json_object *my_array;
    struct json_object *jo1;

    my_array = json_object_new_array();
    json_object_array_add(my_array, json_object_new_int(1));
    json_object_array_add(my_array, json_object_new_int(2));
    json_object_array_add(my_array, json_object_new_int(5));

    json_object_array_insert_idx(my_array, 2, json_object_new_int(4));
    jo1 = json_tokener_parse("[1, 2, 4, 5]");
    assert(1 == json_object_equal(my_array, jo1));
    json_object_put(jo1);

    json_object_array_insert_idx(my_array, 2, json_object_new_int(3));

    jo1 = json_tokener_parse("[1, 2, 3, 4, 5]");
    assert(1 == json_object_equal(my_array, jo1));
    json_object_put(jo1);

    json_object_array_insert_idx(my_array, 5, json_object_new_int(6));

    jo1 = json_tokener_parse("[1, 2, 3, 4, 5, 6]");
    assert(1 == json_object_equal(my_array, jo1));
    json_object_put(jo1);

    json_object_array_insert_idx(my_array, 7, json_object_new_int(8));
    jo1 = json_tokener_parse("[1, 2, 3, 4, 5, 6, null, 8]");
    assert(1 == json_object_equal(my_array, jo1));
    json_object_put(jo1);

    json_object_put(my_array);
}

FUZZ_TEST_SETUP() {
    // One-time initialization tasks
}

FUZZ_TEST(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider
    FuzzedDataProvider fdp(data, size);

    // Use the fuzzer data to create a JSON object
    std::string json_data = fdp.ConsumeRandomLengthString();
    struct json_object *json_obj = json_tokener_parse(json_data.c_str());

    // If json_obj is NULL, return early
    if (json_obj == NULL) {
        return;
    }

    // Fuzz the test_array_insert_idx function
    test_array_insert_idx();

    // Clean up the JSON object
    json_object_put(json_obj);
}
