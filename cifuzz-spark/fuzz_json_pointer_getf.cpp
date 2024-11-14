#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
extern "C" {
  #include "json.h"
}

// FUZZ_TEST_SETUP for one-time initialization tasks
FUZZ_TEST_SETUP() {
  // No one-time initialization tasks needed for this harness
}

// FUZZ_TEST entry point for the fuzzing harness
FUZZ_TEST(const uint8_t *data, size_t size) {
  if (size < 1) {
    return;
  }

  FuzzedDataProvider fdp(data, size);

  // Fuzzing json_tokener_parse
  std::string json_str = fdp.ConsumeRandomLengthString(size);
  struct json_object *jo1 = json_tokener_parse(json_str.c_str());
  if (jo1 == NULL) {
    return;
  }

  // Fuzzing json_pointer_get and json_pointer_getf
  std::string json_pointer = fdp.ConsumeRandomLengthString(size);
  struct json_object *jo2 = NULL;
  json_pointer_get(jo1, json_pointer.c_str(), &jo2);
  json_pointer_getf(jo1, &jo2, "%s", json_pointer.c_str());

  // Fuzzing json_object_get_string
  json_object_get_string(jo1);

  // Fuzzing json_object_is_type and json_object_get_int
  if (json_object_is_type(jo2, json_type_int)) {
    json_object_get_int(jo2);
  }

  // Fuzzing json_pointer_set and json_pointer_setf
  struct json_object *new_obj = json_object_new_string(fdp.ConsumeRandomLengthString(size).c_str());
  int ret_val = 0;
  if (fdp.ConsumeBool()) {
    ret_val = json_pointer_set(&jo1, json_pointer.c_str(), new_obj);
  } else {
    ret_val = json_pointer_setf(&jo1, new_obj, "%s", json_pointer.c_str());
  }
  if (ret_val != 0) {
    json_object_put(new_obj);
  }

  // Clean up
  json_object_put(jo1);
}
