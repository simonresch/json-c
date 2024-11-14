#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include "json.h"
#include "snprintf_compat.h"
extern "C" {
  #include "strerror_override.h"
  #include "json_util.h"
}
#include <fuzzer/FuzzedDataProvider.h>
#include <unistd.h>

// Function declarations
void test_json_patch_op(struct json_object *jo);

FUZZ_TEST_SETUP() {
  // One-time initialization tasks if needed.
}

// The entry point for the fuzzing harness
FUZZ_TEST(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Generate a temporary file with fuzzer data
  char filename[PATH_MAX];
  snprintf(filename, sizeof(filename), "/tmp/fuzzed_file_%d.json", getpid());
  FILE *file = fopen(filename, "w");
  if (file == NULL) {
    return;
  }
  std::string file_content = fdp.ConsumeRandomLengthString(size);
  fwrite(file_content.c_str(), 1, file_content.size(), file);
  fclose(file);

  // Use the generated file to create a json_object
  json_object *jo = json_object_from_file(filename);
  if (!jo) {
    // Clean up the temporary file
    remove(filename);
    return;
  }

  // Fuzz the json_object
  for (size_t ii = 0; ii < json_object_array_length(jo); ii++) {
    struct json_object *jo1 = json_object_array_get_idx(jo, ii);
    test_json_patch_op(jo1);
  }

  // Clean up
  json_object_put(jo);
  remove(filename);
}

// Function definitions
void test_json_patch_op(struct json_object *jo) {
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
}
