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

// Function declaration for json_patch_apply_add_replace
static int json_patch_apply_add_replace(struct json_object **res,
                                        struct json_object *patch_elem,
                                        const char *path, int add, struct json_patch_error *patch_error);

FUZZ_TEST_SETUP() {
  // One time initialization tasks, e.g., memory allocation, file opening.
}

FUZZ_TEST(const uint8_t *data, size_t size) {
  // Initialize FuzzedDataProvider
  FuzzedDataProvider fdp(data, size);

  // Create json_object for patch_elem
  struct json_object *patch_elem = json_tokener_parse(fdp.ConsumeRandomLengthString(100).c_str());
  if (!patch_elem) return;

  // Create json_object for res
  struct json_object *res = json_tokener_parse(fdp.ConsumeRandomLengthString(100).c_str());
  if (!res) {
    json_object_put(patch_elem);
    return;
  }

  // Create path
  std::string path = fdp.ConsumeRandomLengthString(50);

  // Create json_patch_error
  struct json_patch_error patch_error;

  // Call json_patch_apply_add_replace
  int add = fdp.ConsumeBool();
  json_patch_apply_add_replace(&res, patch_elem, path.c_str(), add, &patch_error);

  // Cleanup
  json_object_put(patch_elem);
  json_object_put(res);
}

// Function definition for json_patch_apply_add_replace
static int json_patch_apply_add_replace(struct json_object **res,
                                        struct json_object *patch_elem,
                                        const char *path, int add, struct json_patch_error *patch_error) {
  struct json_object *value;
  int rc;

  if (!json_object_object_get_ex(patch_elem, "value", &value)) {
    patch_error->errno_code = EINVAL;
    patch_error->errmsg = "Patch object does not contain a 'value' field";
    return -1;
  }
  // if this is a replace op, then we need to make sure it exists before replacing
  if (!add && json_pointer_get(*res, path, NULL)) {
    patch_error->errno_code = errno;
    patch_error->errmsg = "path";
    return -1;
  }

  rc = json_pointer_set_with_array_cb(res, path, json_object_get(value),
                                      json_object_array_insert_idx_cb, &add);
  if (rc) {
    patch_error->errno_code = errno;
    patch_error->errmsg = "Failed to set value at path referenced by 'path' field";
    json_object_put(value);
  }

  return rc;
}
