#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "json.h"
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>

FUZZ_TEST_SETUP() {
  // One time initialization tasks, e.g., memory allocation, file opening.
}

FUZZ_TEST(const uint8_t *data, size_t size) {
  // Initialize the FuzzedDataProvider with the input data
  FuzzedDataProvider fdp(data, size);

  // Consume a string from the input data to use as JSON string
  std::string json_str = fdp.ConsumeRandomLengthString(1024);

  // Parse the JSON string
  struct json_object *jo1 = json_tokener_parse(json_str.c_str());
  if (jo1 == NULL) {
    return;
  }

  // Consume a path string from the input data
  std::string path = fdp.ConsumeRandomLengthString(5);

  // Consume a string to use as format string for json_pointer_getf
  std::string getf_path_fmt = fdp.ConsumeRandomLengthString(5);

  // Test json_pointer_getf
  struct json_object *jo2 = NULL;
  json_pointer_getf(jo1, &jo2, "%s", getf_path_fmt.c_str());

  // Test json_pointer_set
  struct json_object *new_jo = json_object_new_object();
  int set_result = json_pointer_set(&jo1, path.c_str(), new_jo);
  if (set_result != 0) {
    json_object_put(new_jo);
  }

  // Test json_pointer_setf
  //std::string setf_path_fmt = fdp.ConsumeRandomLengthString(5);
  std::string setf_path_fmt = fdp.ConsumeRemainingBytesAsString();
  struct json_object *new_jo_setf = json_object_new_object();
  int setf_result = json_pointer_setf(&jo1, new_jo_setf, "%s", setf_path_fmt.c_str());
  if (setf_result != 0) {
    json_object_put(new_jo_setf);
  }

  // Clean up the main JSON object
  json_object_put(jo1);
}
