#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "json.h"

extern "C" {
  #include "strerror_override.h"
  #include "json_util.h"
}

// This function is defined in the test file and used in the fuzz test.
static void test_json_patch_op(struct json_object *jo)
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
		assert(-1 == json_patch_apply(doc, patch, &res, &jperr));
		assert(jperr.errno_code != 0);
		json_object_put(res);
	} else {
		ret = json_patch_apply(doc, patch, &res, &jperr);
		if (ret) {
			assert(0);
		}
		assert(jperr.errno_code == 0);
		ret = json_object_equal(expected, res);
		if (ret == 0) {
			assert(0);
		}
		json_object_put(res);
		res = NULL;
	}
}

FUZZ_TEST_SETUP() {
  // One-time initialization tasks, e.g., memory allocation, file opening.
}

FUZZ_TEST(const uint8_t *data, size_t size) {
  // Initialize FuzzedDataProvider
  FuzzedDataProvider fdp(data, size);

  // Create a temporary file to store fuzzer data
  char filename[] = "/tmp/fuzz_jsonXXXXXX";
  int fd = mkstemp(filename);
  if (fd < 0) {
    return;
  }

  // Write fuzzer data to the temporary file
  write(fd, data, size);
  close(fd);

  // Test json_object_from_file
  struct json_object *jo = json_object_from_file(filename);
  if (jo != NULL) {
    json_object_put(jo);
  }

  // Test json_object_from_fd
  fd = open(filename, O_RDONLY);
  if (fd >= 0) {
    jo = json_object_from_fd(fd);
    if (jo != NULL) {
      json_object_put(jo);
    }
    close(fd);
  }

  // Test json_object_from_fd_ex
  fd = open(filename, O_RDONLY);
  if (fd >= 0) {
    jo = json_object_from_fd_ex(fd, fdp.ConsumeIntegralInRange<int>(-1, 100));
    if (jo != NULL) {
      json_object_put(jo);
    }
    close(fd);
  }

  // Test json_patch_op if the json object is an array
  fd = open(filename, O_RDONLY);
  if (fd >= 0) {
    jo = json_object_from_fd(fd);
    if (jo != NULL && json_object_get_type(jo) == json_type_array) {
      for (size_t ii = 0; ii < json_object_array_length(jo); ii++) {
        struct json_object *jo1 = json_object_array_get_idx(jo, ii);
        test_json_patch_op(jo1);
      }
    }
    json_object_put(jo);
    close(fd);
  }

  // Clean up the temporary file
  unlink(filename);
}
