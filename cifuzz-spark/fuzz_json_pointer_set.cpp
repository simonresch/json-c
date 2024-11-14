#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <cifuzz/cifuzz.h>
#include <json.h>
#include <fuzzer/FuzzedDataProvider.h>

// The FUZZ_TEST_SETUP() macro is used for one-time initialization tasks.
FUZZ_TEST_SETUP() {
  // No one-time initialization tasks are needed for this harness.
}

// The entry point for the fuzzing harness is the FUZZ_TEST function.
FUZZ_TEST(const uint8_t *data, size_t size) {
  // Initialize the FuzzedDataProvider with the input data.
  FuzzedDataProvider fdp(data, size);

  // Fuzzing json_tokener_parse and json_pointer_set functions
  const char *input_json_str = "{ "
                               "'foo': ['bar', 'baz'], "
                               "'': 0, "
                               "'a/b': 1, "
                               "'c%d': 2, "
                               "'e^f': 3, "
                               "'g|h': 4, "
                               "'i\\\\j': 5, "
                               "'k\\\"l': 6, "
                               "' ': 7, "
                               "'m~n': 8 "
                               "}";

  struct json_object *jo1 = json_tokener_parse(input_json_str);
  if (jo1 == NULL) {
    return;
  }

  // Fuzz json_pointer_set with random strings and json_object
  std::string json_pointer = fdp.ConsumeRandomLengthString(100);
  struct json_object *new_value = json_object_new_string(fdp.ConsumeRandomLengthString(100).c_str());

  // Increase reference count for jo1 and new_value to avoid premature free
  json_object_get(jo1);
  json_object_get(new_value);

  json_pointer_set(&jo1, json_pointer.c_str(), new_value);

  // Fuzz json_pointer_setf with random format strings and json_object
  std::string format_string = fdp.ConsumeRandomLengthString(100);
  struct json_object *new_value_f = json_object_new_string(fdp.ConsumeRandomLengthString(100).c_str());

  // Increase reference count for new_value_f to avoid premature free
  json_object_get(new_value_f);

  json_pointer_setf(&jo1, new_value_f, format_string.c_str());

  // Clean up json objects
  json_object_put(jo1);
  json_object_put(new_value);
  json_object_put(new_value_f);
}
