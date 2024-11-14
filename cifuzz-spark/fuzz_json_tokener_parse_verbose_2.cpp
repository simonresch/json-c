#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "json.h"
extern "C" {
  #include "json_tokener.h"
  #include "json_util.h"
  #include "json_object.h"
  #include "json_object_private.h"
  #include "json_visit.h"
  #include "printbuf.h"
}

static int emit_object(json_object *jso, int flags, json_object *parent_jso, const char *jso_key,
                       size_t *jso_index, void *userarg) {
  return JSON_C_VISIT_RETURN_CONTINUE;
}

FUZZ_TEST_SETUP() {
  // One time initialization tasks, e.g., memory allocation, file opening.
}

FUZZ_TEST(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Example 1: json_tokener_parse
  std::string json_str = fdp.ConsumeRandomLengthString();
  struct json_object *obj = json_tokener_parse(json_str.c_str());
  if (obj) {
    json_object_put(obj);
  }

  // Example 2: json_object_array_add and json_object_array_insert_idx
  json_object *my_array = json_object_new_array();
  if (my_array) {
    for (int i = 0; i < 5; ++i) {
      json_object_array_add(my_array, json_object_new_int(fdp.ConsumeIntegral<int>()));
    }
    json_object_array_insert_idx(my_array, fdp.ConsumeIntegralInRange<size_t>(0, 4), json_object_new_int(fdp.ConsumeIntegral<int>()));
    json_object_put(my_array);
  }

  // Example 3: json_object_to_json_string
  json_object *new_obj = json_tokener_parse(json_str.c_str());
  if (new_obj) {
    const char *json_output = json_object_to_json_string(new_obj);
    (void)json_output; // to avoid unused variable warning
    json_object_put(new_obj);
  }

  // Example 4: json_object_get_string and json_object_get_int
  json_object *parsed_obj = json_tokener_parse(json_str.c_str());
  if (parsed_obj) {
    const char *string_val = json_object_get_string(parsed_obj);
    int int_val = json_object_get_int(parsed_obj);
    (void)string_val; // to avoid unused variable warning
    (void)int_val; // to avoid unused variable warning
    json_object_put(parsed_obj);
  }

  // Example 5: json_object_deep_copy
  json_object *src = json_tokener_parse(json_str.c_str());
  if (src) {
    json_object *dst = NULL;
    if (json_object_deep_copy(src, &dst, NULL) == 0) {
      json_object_put(dst);
    }
    json_object_put(src);
  }

  // Example 6: json_pointer_get
  json_object *json_obj = json_tokener_parse(json_str.c_str());
  if (json_obj) {
    struct json_object *result = NULL;
    std::string pointer = fdp.ConsumeRandomLengthString();
    json_pointer_get(json_obj, pointer.c_str(), &result);
    if (result) {
      json_object_put(result);
    }
    json_object_put(json_obj);
  }

  // Example 7: json_object_set_string and json_object_get_double
  json_object *string_obj = json_object_new_string(json_str.c_str());
  if (string_obj) {
    json_object_set_string(string_obj, json_str.c_str());
    double double_val = json_object_get_double(string_obj);
    (void)double_val; // to avoid unused variable warning
    json_object_put(string_obj);
  }

  // Example 8: json_object_to_file and json_object_from_file
  json_object *file_obj = json_tokener_parse(json_str.c_str());
  if (file_obj) {
    const char *temp_file = "/tmp/json_fuzz_test.json";
    json_object_to_file(temp_file, file_obj);
    json_object *read_obj = json_object_from_file(temp_file);
    if (read_obj) {
      json_object_put(read_obj);
    }
    json_object_put(file_obj);
  }

  // Example 9: json_c_visit
  json_object *visit_obj = json_tokener_parse(json_str.c_str());
  if (visit_obj) {
    json_c_visit(visit_obj, 0, emit_object, NULL);
    json_object_put(visit_obj);
  }
}
