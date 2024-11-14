#include "json.h"
#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <stdarg.h>
#include <iostream>

// Function copied from the provided test file
static void test_example_int(struct json_object *jo1, const char *json_pointer, int expected_int)
{
	struct json_object *jo2 = NULL;
	json_pointer_get(jo1, json_pointer, NULL);
	json_pointer_get(jo1, json_pointer, &jo2);
	json_object_is_type(jo2, json_type_int);
	json_object_get_int(jo2);
}

FUZZ_TEST_SETUP()
{
	// One time initialization tasks, e.g., memory allocation, file opening.
}

FUZZ_TEST(const uint8_t *data, size_t size)
{
	FuzzedDataProvider fdp(data, size);

	// Fuzzing the json_tokener_parse function with provided data
	std::string jsonString = fdp.ConsumeRandomLengthString();
	struct json_object *jo1 = json_tokener_parse(jsonString.c_str());
	if (jo1 == NULL) {
	  return;
	}

	std::cerr << "jsonString: " << jsonString << std::endl;

	// Fuzzing json_pointer_get function
	std::string jsonPointer = fdp.ConsumeRandomLengthString();
	struct json_object *jo2 = NULL;
	json_pointer_get(jo1, jsonPointer.c_str(), &jo2);

	// Fuzzing json_pointer_getf function
	std::string format = fdp.ConsumeRandomLengthString();
	json_pointer_getf(jo1, &jo2, "%s", format.c_str());

	// Fuzzing json_object_get_string function
	json_object_get_string(jo1);

	// Fuzzing json_object_is_type function
	json_object_is_type(jo2, json_type_int);
	json_object_is_type(jo2, json_type_string);

	// Fuzzing json_object_get_int function
	json_object_get_int(jo2);

	// Fuzzing the test_example_int function
	std::string jsonPointerInt = fdp.ConsumeRandomLengthString();
	int expectedInt = fdp.ConsumeIntegral<int>();
	test_example_int(jo1, jsonPointerInt.c_str(), expectedInt);

	// Clean up
	json_object_put(jo1);
}
