#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "json.h"
#include "json_tokener.h"
#include "json_util.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <cifuzz/cifuzz.h>

FUZZ_TEST_SETUP() {
  // One-time initialization tasks, if any.
}

FUZZ_TEST(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Fuzzing json_object_array_add and json_object_array_insert_idx
  json_object *my_array = json_object_new_array();
  json_object_array_add(my_array, json_object_new_int(fdp.ConsumeIntegral<int>()));
  json_object_array_add(my_array, json_object_new_int(fdp.ConsumeIntegral<int>()));
  json_object_array_add(my_array, json_object_new_int(fdp.ConsumeIntegral<int>()));
  json_object_array_insert_idx(my_array, fdp.ConsumeIntegralInRange<size_t>(0, 2), json_object_new_int(fdp.ConsumeIntegral<int>()));
  json_object_put(my_array);

  // Fuzzing json_tokener_parse and json_object_to_json_string
  std::string json_string = fdp.ConsumeRandomLengthString();
  json_object *parsed_obj = json_tokener_parse(json_string.c_str());
  if (parsed_obj) {
    const char *json_str = json_object_to_json_string(parsed_obj);
    (void)json_str; // Suppress unused variable warning
    json_object_put(parsed_obj);
  }

  // Fuzzing json_object_new_string_len and json_tokener_parse
  std::string input_str = fdp.ConsumeRandomLengthString();
  struct json_object *string_obj = json_object_new_string_len(input_str.c_str(), input_str.size());
  const char *json = json_object_to_json_string(string_obj);
  struct json_object *parsed_str = json_tokener_parse(json);
  if (parsed_str) {
    json_object_put(parsed_str);
  }
  json_object_put(string_obj);

  // Fuzzing json_object_from_file and json_object_to_file
  std::string file_content = fdp.ConsumeRandomLengthString();
  char tmp_filename[] = "/tmp/json_fuzz_XXXXXX";
  int fd = mkstemp(tmp_filename);
  if (fd != -1) {
    write(fd, file_content.c_str(), file_content.size());
    close(fd);

    struct json_object *file_obj = json_object_from_file(tmp_filename);
    if (file_obj) {
      json_object_to_file(tmp_filename, file_obj);
      json_object_put(file_obj);
    }

    unlink(tmp_filename);
  }
}
