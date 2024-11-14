#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "json.h"

extern "C" {
  #include "strerror_override.h"
}

// Function copied from the provided source code
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

	if (!error && !have_expected) {
		return;
	}
	struct json_patch_error jperr;
	if (error) {
		if (-1 != json_patch_apply(doc, patch, &res, &jperr) || jperr.errno_code == 0) {
			json_object_put(res);
			return;
		}
		json_object_put(res);
	} else {
		ret = json_patch_apply(doc, patch, &res, &jperr);
		if (ret) {
			json_object_put(res);
			return;
		}
		if (jperr.errno_code != 0 || json_object_equal(expected, res) == 0) {
			json_object_put(res);
			return;
		}
		json_object_put(res);
		res = NULL;
	}
}

FUZZ_TEST(const uint8_t *data, size_t size) {
	// Initialize FuzzedDataProvider
	FuzzedDataProvider fdp(data, size);

	// Create a JSON object from the fuzzer data
	std::string json_str = fdp.ConsumeRandomLengthString(size);
	struct json_object *jo = json_tokener_parse(json_str.c_str());

	// Ensure the JSON object is valid
	if (jo == NULL) {
		return;
	}

	// Execute the test function with the JSON object
	test_json_patch_op(jo);

	// Clean up the JSON object
	json_object_put(jo);
}
