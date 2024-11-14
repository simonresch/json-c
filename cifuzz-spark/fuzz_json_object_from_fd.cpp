#include <assert.h>
#include <cifuzz/cifuzz.h>
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

// Include necessary headers within extern "C" to prevent name mangling
extern "C" {
  #include "strerror_override.h"
  #include "json_util.h"
}

// Structure of the fuzz test:
// 1. Setup function to initialize any required resources.
// 2. Fuzz test entry function to test the relevant API functions using fuzzer-generated data.

FUZZ_TEST_SETUP() {
  // One-time initialization tasks, if any.
}

FUZZ_TEST(const uint8_t *data, size_t size) {
  // Utilize FuzzedDataProvider to handle fuzzer-generated input.
  FuzzedDataProvider fdp(data, size);

  // Generate a temporary file to use with json_object_from_file.
  const char *tmp_filename = "/tmp/fuzz_json_file.json";
  FILE *tmp_file = fopen(tmp_filename, "wb");
  if (tmp_file == nullptr) {
    return;
  }
  std::vector<uint8_t> file_content = fdp.ConsumeBytes<uint8_t>(fdp.remaining_bytes());
  fwrite(file_content.data(), 1, file_content.size(), tmp_file);
  fclose(tmp_file);

  // Test json_object_from_file function.
  struct json_object *json_obj = json_object_from_file(tmp_filename);
  if (json_obj != nullptr) {
    json_object_put(json_obj);
  }

  // Test json_object_from_fd function.
  int fd = open(tmp_filename, O_RDONLY);
  if (fd >= 0) {
    json_obj = json_object_from_fd(fd);
    if (json_obj != nullptr) {
      json_object_put(json_obj);
    }
    close(fd);
  }

  // Test json_object_to_file and json_object_to_file_ext functions.
  std::string json_str = fdp.ConsumeRandomLengthString(4096);
  json_obj = json_tokener_parse(json_str.c_str());
  if (json_obj != nullptr) {
    json_object_to_file("/tmp/fuzz_json_out.json", json_obj);
    json_object_to_file_ext("/tmp/fuzz_json_out_ext.json", json_obj, JSON_C_TO_STRING_PRETTY);
    json_object_put(json_obj);
  }

  // Test json_object_array_length and json_object_array_get_idx functions.
  json_obj = json_tokener_parse(json_str.c_str());
  if (json_obj != nullptr && json_object_get_type(json_obj) == json_type_array) {
    size_t array_length = json_object_array_length(json_obj);
    for (size_t i = 0; i < array_length; ++i) {
      struct json_object *elem = json_object_array_get_idx(json_obj, i);
      if (elem != nullptr) {
        // Do something with elem if needed.
      }
    }
    json_object_put(json_obj);
  }

  // Test json_util_get_last_err function.
  const char *last_err = json_util_get_last_err();
  if (last_err != nullptr) {
    // Do something with last_err if needed.
  }

  // Clean up the temporary file.
  remove(tmp_filename);
}
