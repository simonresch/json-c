#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "json.h"
#include "json_tokener.h"
#include "json_util.h"
#include "json_visit.h"
#include "json_object.h"
#include "json_object_iterator.h"

FUZZ_TEST_SETUP() {
  // One time initialization tasks, e.g., memory allocation, file opening.
}

FUZZ_TEST(const uint8_t *data, size_t size) {
  // Initialize the FuzzedDataProvider with the input data
  FuzzedDataProvider fdp(data, size);

  // Fuzzing json_tokener_parse
  std::string json_str = fdp.ConsumeRandomLengthString();
  struct json_object *parsed_obj = json_tokener_parse(json_str.c_str());
  if (parsed_obj) {
    json_object_put(parsed_obj);
  }

  // Fuzzing json_object_new_int and json_object_set_int
  int32_t int_val = fdp.ConsumeIntegral<int32_t>();
  struct json_object *int_obj = json_object_new_int(int_val);
  if (int_obj) {
    int32_t new_int_val = fdp.ConsumeIntegral<int32_t>();
    json_object_set_int(int_obj, new_int_val);
    json_object_put(int_obj);
  }

  // Fuzzing json_object_new_double and json_object_set_double
  double double_val = fdp.ConsumeFloatingPoint<double>();
  struct json_object *double_obj = json_object_new_double(double_val);
  if (double_obj) {
    double new_double_val = fdp.ConsumeFloatingPoint<double>();
    json_object_set_double(double_obj, new_double_val);
    json_object_put(double_obj);
  }

  // Fuzzing json_object_new_string and json_object_set_string
  std::string string_val = fdp.ConsumeRandomLengthString();
  struct json_object *string_obj = json_object_new_string(string_val.c_str());
  if (string_obj) {
    std::string new_string_val = fdp.ConsumeRandomLengthString();
    json_object_set_string(string_obj, new_string_val.c_str());
    json_object_put(string_obj);
  }

  // Fuzzing json_tokener_parse_verbose
  enum json_tokener_error error;
  struct json_object *verbose_obj = json_tokener_parse_verbose(json_str.c_str(), &error);
  if (verbose_obj) {
    json_object_put(verbose_obj);
  }

  // Fuzzing json_object_to_json_string
  if (parsed_obj) {
    const char *json_output = json_object_to_json_string(parsed_obj);
  }

  // Fuzzing json_object_array_add and json_object_array_insert_idx
  struct json_object *array_obj = json_object_new_array();
  if (array_obj) {
    struct json_object *elem_obj = json_object_new_int(fdp.ConsumeIntegral<int32_t>());
    json_object_array_add(array_obj, elem_obj);

    size_t idx = fdp.ConsumeIntegral<size_t>();
    struct json_object *insert_elem_obj = json_object_new_int(fdp.ConsumeIntegral<int32_t>());
    json_object_array_insert_idx(array_obj, idx, insert_elem_obj);

    json_object_put(array_obj);
  }

  // Fuzzing json_object_to_file
  struct json_object *file_obj = json_tokener_parse(json_str.c_str());
  if (file_obj) {
    std::string temp_file = "/tmp/json_fuzz_test.json";
    json_object_to_file(temp_file.c_str(), file_obj);
    json_object_put(file_obj);
  }
}
