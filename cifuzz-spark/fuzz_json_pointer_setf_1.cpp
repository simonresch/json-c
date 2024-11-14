#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "json.h"
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>

// One-time setup for the fuzz test
FUZZ_TEST_SETUP() {
  // No specific setup required for this fuzz test
}

// Entry point for the fuzz test
FUZZ_TEST(const uint8_t *data, size_t size) {
  // Use FuzzedDataProvider to handle the fuzzer input data
  FuzzedDataProvider fdp(data, size);

  // Generate a JSON string from the fuzzer data
  std::string json_str = fdp.ConsumeRandomLengthString(1024);
  struct json_object *jo1 = json_tokener_parse(json_str.c_str());

  if (jo1 == NULL) {
    return;
  }

  // Fuzz json_pointer_set and json_pointer_setf
  std::string json_pointer = fdp.ConsumeRandomLengthString(256);
  struct json_object *new_value = json_object_new_string(fdp.ConsumeRandomLengthString(256).c_str());
  json_pointer_set(&jo1, json_pointer.c_str(), new_value);

  json_pointer = fdp.ConsumeRandomLengthString(256);
  new_value = json_object_new_string(fdp.ConsumeRandomLengthString(256).c_str());
  json_pointer_setf(&jo1, new_value, "%s", json_pointer.c_str());

  // Fuzz json_pointer_get and json_pointer_getf
  struct json_object *jo2 = NULL;
  json_pointer_get(jo1, json_pointer.c_str(), &jo2);

  json_pointer = fdp.ConsumeRandomLengthString(256);
  json_pointer_getf(jo1, &jo2, "%s", json_pointer.c_str());

  // Clean up
  json_object_put(jo1);
}
