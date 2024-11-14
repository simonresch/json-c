#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "json.h"
#include "json_util.h"

// Function prototypes
void test_json_patch_op(struct json_object *jo);

// Function implementations
void test_json_patch_op(struct json_object *jo)
{
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

FUZZ_TEST_SETUP() {
  // One-time initialization tasks, e.g., memory allocation, file opening.
}

FUZZ_TEST(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Create a temporary file to use with json_object_from_file
  char filename[] = "/tmp/fuzz_json.XXXXXX";
  int fd = mkstemp(filename);
  if (fd == -1) {
    return;
  }

  std::string file_content = fdp.ConsumeRandomLengthString(size);
  write(fd, file_content.c_str(), file_content.size());
  close(fd);

  // Fuzz json_object_from_file
  json_object *jo = json_object_from_file(filename);
  if (jo) {
    for (size_t ii = 0; ii < json_object_array_length(jo); ii++) {
      struct json_object *jo1 = json_object_array_get_idx(jo, ii);
      test_json_patch_op(jo1);
    }
    json_object_put(jo);
  }

  // Clean up the temporary file
  unlink(filename);
}
