#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
  #include "json_patch.h"
  #include "json_object_private.h"
  #include "json_pointer_private.h"
  #include "json.h"
}

// Structure of the fuzz test:
// 1. Setup the necessary initialization using FUZZ_TEST_SETUP().
// 2. Implement the FUZZ_TEST() function to perform fuzz testing on the target functions.

FUZZ_TEST_SETUP() {
  // One time initialization tasks, if any.
}

// Function to apply a JSON patch using fuzzed data
void apply_json_patch(FuzzedDataProvider &fdp) {
  struct json_object *base = json_tokener_parse(fdp.ConsumeRandomLengthString(100).c_str());
  struct json_object *patch = json_tokener_parse(fdp.ConsumeRandomLengthString(100).c_str());
  struct json_object *res = NULL;
  struct json_patch_error patch_error;

  if (base && patch) {
    json_patch_apply(base, patch, &res, &patch_error);
  }

  json_object_put(base);
  json_object_put(patch);
  json_object_put(res);
}

// Function to set a JSON pointer using fuzzed data
void set_json_pointer(FuzzedDataProvider &fdp) {
  struct json_object *obj = json_tokener_parse(fdp.ConsumeRandomLengthString(100).c_str());
  std::string path = fdp.ConsumeRandomLengthString(50);
  struct json_object *value = json_tokener_parse(fdp.ConsumeRandomLengthString(50).c_str());

  if (obj && value) {
    json_pointer_set(&obj, path.c_str(), value);
  }

  json_object_put(obj);
  json_object_put(value);
}

// Function to test JSON patch operations using fuzzed data
void test_json_patch_op(FuzzedDataProvider &fdp) {
  struct json_object *jo = json_tokener_parse(fdp.ConsumeRandomLengthString(100).c_str());
  if (!jo) return;

  const char *comment = json_object_get_string(json_object_object_get(jo, "comment"));
  struct json_object *doc = json_object_object_get(jo, "doc");
  struct json_object *patch = json_object_object_get(jo, "patch");
  struct json_object *expected = NULL;
  json_bool have_expected = json_object_object_get_ex(jo, "expected", &expected);
  struct json_object *error = json_object_object_get(jo, "error");
  const char *error_s = json_object_get_string(error);
  struct json_object *res = NULL;
  int ret;

  struct json_patch_error jperr;
  if (error) {
    json_patch_apply(doc, patch, &res, &jperr);
    json_object_put(res);
  } else {
    ret = json_patch_apply(doc, patch, &res, &jperr);
    if (ret == 0) {
      json_object_equal(expected, res);
    }
    json_object_put(res);
  }

  json_object_put(jo);
}

FUZZ_TEST(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Apply JSON patch
  apply_json_patch(fdp);

  // Set JSON pointer
  set_json_pointer(fdp);

  // Test JSON patch operations
  test_json_patch_op(fdp);
}
