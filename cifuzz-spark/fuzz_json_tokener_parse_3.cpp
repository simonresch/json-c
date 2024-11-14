#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "json.h"
#include "json_tokener.h"
#include "json_visit.h"
#include "json_util.h"
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>

// Function to test json_object_array_insert_idx
void test_array_insert_idx(FuzzedDataProvider &fdp) {
    json_object *my_array = json_object_new_array();
    for (int i = 0; i < 3; ++i) {
        json_object_array_add(my_array, json_object_new_int(fdp.ConsumeIntegral<int>()));
    }
    json_object_array_insert_idx(my_array, fdp.ConsumeIntegralInRange<size_t>(0, 2), json_object_new_int(fdp.ConsumeIntegral<int>()));
    json_object_put(my_array);
}

// Function to test json_tokener_parse and json_object_to_json_string
void test_json_tokener_parse(FuzzedDataProvider &fdp) {
    std::string json_string = fdp.ConsumeRandomLengthString(100);
    json_object *new_obj = json_tokener_parse(json_string.c_str());
    if (new_obj != NULL) {
        json_object_to_json_string(new_obj);
        json_object_put(new_obj);
    }
}

// Function to test json_object_set functions
void test_json_object_set(FuzzedDataProvider &fdp) {
    json_object *tmp = json_object_new_int(fdp.ConsumeIntegral<int>());
    json_object_set_int(tmp, fdp.ConsumeIntegral<int>());
    json_object_set_int64(tmp, fdp.ConsumeIntegral<int64_t>());
    json_object_set_uint64(tmp, fdp.ConsumeIntegral<uint64_t>());
    json_object_set_double(tmp, fdp.ConsumeFloatingPoint<double>());
    json_object_set_string(tmp, fdp.ConsumeRandomLengthString(50).c_str());
    json_object_put(tmp);
}

// Function to test json_object_to_file and json_object_from_file
void test_json_object_file_operations(FuzzedDataProvider &fdp) {
    json_object *jso = json_object_new_object();
    json_object_object_add(jso, "key", json_object_new_string(fdp.ConsumeRandomLengthString(50).c_str()));

    const char *outfile = "/tmp/json.out";
    json_object_to_file(outfile, jso);

    json_object *jso_from_file = json_object_from_file(outfile);
    if (jso_from_file != NULL) {
        json_object_put(jso_from_file);
    }

    json_object_put(jso);
}

// Function to test json_c_visit
static int emit_object(json_object *jso, int flags, json_object *parent_jso, const char *jso_key, size_t *jso_index, void *userarg) {
    return JSON_C_VISIT_RETURN_CONTINUE;
}

void test_json_c_visit(FuzzedDataProvider &fdp) {
    std::string json_string = fdp.ConsumeRandomLengthString(100);
    json_object *jso = json_tokener_parse(json_string.c_str());
    if (jso != NULL) {
        json_c_visit(jso, 0, emit_object, NULL);
        json_object_put(jso);
    }
}

FUZZ_TEST(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    test_array_insert_idx(fdp);
    test_json_tokener_parse(fdp);
    test_json_object_set(fdp);
    test_json_object_file_operations(fdp);
    test_json_c_visit(fdp);
}
