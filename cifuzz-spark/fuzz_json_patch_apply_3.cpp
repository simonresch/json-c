#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "config.h"
#include "json.h"
#include "snprintf_compat.h"

extern "C" {
  #include "strerror_override.h"
}

// Structure of the fuzz test:
// 1. Setup any necessary one-time initialization using FUZZ_TEST_SETUP().
// 2. Define the FUZZ_TEST() function which will use the fuzzer-generated input to test the target functions.

FUZZ_TEST_SETUP() {
  // One time initialization tasks, e.g., memory allocation, file opening.
}

FUZZ_TEST(const uint8_t *data, size_t size) {
  // Initialize FuzzedDataProvider with the input data.
  FuzzedDataProvider fdp(data, size);

  // Create a JSON object from the fuzzer input data.
  std::string json_data = fdp.ConsumeRemainingBytesAsString();
  struct json_object *jo = json_tokener_parse(json_data.c_str());
  if (!jo) {
    return; // If parsing fails, exit early.
  }

  // Extract relevant JSON objects.
  struct json_object *doc = json_object_object_get(jo, "doc");
  struct json_object *patch = json_object_object_get(jo, "patch");
  struct json_object *expected = NULL;
  json_bool have_expected = json_object_object_get_ex(jo, "expected", &expected);
  struct json_object *error = json_object_object_get(jo, "error");
  struct json_object *res = NULL;
  struct json_patch_error jperr;

  // Apply the JSON patch.
  if (error) {
    json_patch_apply(doc, patch, &res, &jperr);
  } else {
    int ret = json_patch_apply(doc, patch, &res, &jperr);
    if (ret == 0 && have_expected) {
      json_object_equal(expected, res);
    }
  }

  // Cleanup.
  json_object_put(jo);
  json_object_put(res);
}
