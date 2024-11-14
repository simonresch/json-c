#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <fuzzer/FuzzedDataProvider.h>
extern "C" {
  #include "json_object.h"
  #include "json_tokener.h"
  #include "json_util.h"
}

// The FUZZ_TEST_SETUP() macro is used for one-time initialization tasks.
FUZZ_TEST_SETUP() {
  // One-time initialization tasks, e.g., memory allocation, file opening.
}

// The entry point for the fuzzing harness is the FUZZ_TEST function.
FUZZ_TEST(const uint8_t *data, size_t size) {
  // Use FuzzedDataProvider to consume the fuzzer-generated input.
  FuzzedDataProvider fdp(data, size);

  // Consume a random length string from the input data.
  std::string json_str = fdp.ConsumeRandomLengthString();

  // Parse the JSON string using json_tokener_parse.
  struct json_object *parsed_obj = json_tokener_parse(json_str.c_str());

  // If the parsed object is not NULL, perform some operations on it.
  if (parsed_obj != NULL) {
    // Convert the parsed object back to a JSON string.
    const char *json_output = json_object_to_json_string(parsed_obj);

    // Free the parsed object.
    json_object_put(parsed_obj);
  }

  // Consume another random length string from the input data.
  std::string json_str2 = fdp.ConsumeRandomLengthString();

  // Parse the JSON string using json_tokener_parse_ex with a new tokener.
  struct json_tokener *tok = json_tokener_new();
  struct json_object *parsed_obj2 = json_tokener_parse_ex(tok, json_str2.c_str(), json_str2.length());
  json_tokener_free(tok);

  // If the parsed object is not NULL, perform some operations on it.
  if (parsed_obj2 != NULL) {
    // Convert the parsed object back to a JSON string.
    const char *json_output2 = json_object_to_json_string(parsed_obj2);

    // Free the parsed object.
    json_object_put(parsed_obj2);
  }

  // Consume a random integral value from the input data for depth.
  int depth = fdp.ConsumeIntegralInRange<int>(1, JSON_TOKENER_DEFAULT_DEPTH);

  // Create a new json_tokener with the consumed depth.
  json_tokener *tok2 = json_tokener_new_ex(depth);

  // If the tokener is successfully created, parse the JSON string using it.
  if (tok2 != NULL) {
    struct json_object *parsed_obj3 = json_tokener_parse_ex(tok2, json_str.c_str(), json_str.length());

    // Free the tokener.
    json_tokener_free(tok2);

    // If the parsed object is not NULL, perform some operations on it.
    if (parsed_obj3 != NULL) {
      // Convert the parsed object back to a JSON string.
      const char *json_output3 = json_object_to_json_string(parsed_obj3);

      // Free the parsed object.
      json_object_put(parsed_obj3);
    }
  }
}
