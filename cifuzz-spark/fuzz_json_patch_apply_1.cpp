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

// Function to test JSON patch operation
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
		if (-1 != json_patch_apply(doc, patch, &res, &jperr)) {
			return;
		}
		if (jperr.errno_code == 0) {
			return;
		}
		json_object_put(res);
	} else {
		ret = json_patch_apply(doc, patch, &res, &jperr);
		if (ret) {
			return;
		}
		if (jperr.errno_code != 0) {
			return;
		}
		ret = json_object_equal(expected, res);
		if (ret == 0) {
			return;
		}
		json_object_put(res);
		res = NULL;
	}
}

FUZZ_TEST(const uint8_t *data, size_t size) {
	// Initialize FuzzedDataProvider with the input data
	FuzzedDataProvider fdp(data, size);
	
	// Consume a random length string from the input data to create a JSON string
	std::string json_string = fdp.ConsumeRandomLengthString();

	// Parse the JSON string into a json_object
	struct json_object *jo = json_tokener_parse(json_string.c_str());
	if (jo == NULL) {
		return;
	}
	
	// Call the test function with the created json_object
	test_json_patch_op(jo);
	
	// Clean up the json_object
	json_object_put(jo);
}
