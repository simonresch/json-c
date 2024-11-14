#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
extern "C" {
  #include "json_patch.h"
  #include "json_object_private.h"
  #include "json_pointer_private.h"
  #include "json_tokener.h"
}

FUZZ_TEST_SETUP() {
  // One time initialization tasks, e.g., memory allocation, file opening.
}

FUZZ_TEST(const uint8_t *data, size_t size) {
  // Initialize FuzzedDataProvider with fuzzer input data
  FuzzedDataProvider fdp(data, size);

  // Create a json_object from fuzzer data
  struct json_object *doc = json_tokener_parse(fdp.ConsumeRandomLengthString().c_str());
  struct json_object *patch = json_tokener_parse(fdp.ConsumeRandomLengthString().c_str());
  struct json_object *res = NULL;
  struct json_patch_error patch_error;

  // Apply a JSON patch
  json_patch_apply(doc, patch, &res, &patch_error);

  // Clean up
  json_object_put(doc);
  json_object_put(patch);
  json_object_put(res);
}
