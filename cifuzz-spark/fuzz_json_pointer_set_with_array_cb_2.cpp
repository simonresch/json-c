#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
  #include "json.h"
  #include "json_patch.h"
  #include "json_object_private.h"
  #include "json_pointer.h"
  #include "json_pointer_private.h"
  #include "strerror_override.h"
}

FUZZ_TEST_SETUP() {
  // One time initialization tasks, e.g., memory allocation, file opening.
}

FUZZ_TEST(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Generate random JSON strings
  std::string json_str1 = fdp.ConsumeRandomLengthString(1024);
  std::string json_str2 = fdp.ConsumeRandomLengthString(1024);
  std::string json_str3 = fdp.ConsumeRandomLengthString(1024);

  // Parse JSON objects from strings
  struct json_object *doc = json_tokener_parse(json_str1.c_str());
  struct json_object *patch = json_tokener_parse(json_str2.c_str());
  struct json_object *expected = json_tokener_parse(json_str3.c_str());

  if (doc && patch) {
    struct json_object *res = NULL;
    struct json_patch_error patch_error;

    // Apply the patch
    json_patch_apply(doc, patch, &res, &patch_error);

    // Clean up
    json_object_put(doc);
    json_object_put(patch);
    if (res) {
      json_object_put(res);
    }
  }

  if (expected) {
    json_object_put(expected);
  }
}
