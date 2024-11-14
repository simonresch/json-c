#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "json.h"
#include <cifuzz/cifuzz.h>

// The FUZZ_TEST_SETUP() macro for one-time initialization tasks
FUZZ_TEST_SETUP() {
  // One time initialization tasks, e.g., memory allocation, file opening.
}

// The entry point for the fuzzing harness is the FUZZ_TEST function
FUZZ_TEST(const uint8_t *data, size_t size) {
  // Use FuzzedDataProvider to create input data from the fuzzer
  FuzzedDataProvider fdp(data, size);

  // Generate a random JSON string
  std::string json_str = fdp.ConsumeRandomLengthString(size);

  // Parse the JSON string
  struct json_object *jo1 = json_tokener_parse(json_str.c_str());

  // If the JSON object is NULL, exit early
  if (jo1 == NULL) {
    return;
  }

  // Generate a random JSON pointer
  std::string json_pointer = fdp.ConsumeRandomLengthString(size);

  // Generate a random JSON value
  struct json_object *jo2 = json_tokener_parse(fdp.ConsumeRandomLengthString(size).c_str());

  // Test json_pointer_set
  json_pointer_set(&jo1, json_pointer.c_str(), jo2);

  // Test json_pointer_setf
  json_pointer_setf(&jo1, jo2, "%s", json_pointer.c_str());

  // Test json_pointer_get
  struct json_object *jo3 = NULL;
  json_pointer_get(jo1, json_pointer.c_str(), &jo3);

  // Test json_pointer_getf
  json_pointer_getf(jo1, &jo3, "%s", json_pointer.c_str());

  // Test json_object_get_string
  json_object_get_string(jo1);

  // Test json_object_equal
  json_object_equal(jo1, jo2);

  // Test json_object_put
  json_object_put(jo1);
  json_object_put(jo2);
  json_object_put(jo3);

  // Generate a random integer
  int random_int = fdp.ConsumeIntegral<int>();

  // Test json_object_new_int
  struct json_object *jo4 = json_object_new_int(random_int);

  // Test json_object_get_int
  json_object_get_int(jo4);

  // Clean up
  json_object_put(jo4);
}
