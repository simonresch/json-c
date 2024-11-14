#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/time.h>
extern "C" {
  #include "json_object.h"
  #include "json_tokener.h"
  #include "json_util.h"
}

// One-time setup function
FUZZ_TEST_SETUP() {
  // No one-time setup needed for this fuzz test
}

// Fuzzing entry point
FUZZ_TEST(const uint8_t *data, size_t size) {
  // Initialize FuzzedDataProvider
  FuzzedDataProvider fdp(data, size);

  // Consume an integer to decide the function to fuzz
  int choice = fdp.ConsumeIntegralInRange<int>(0, 5);

  // Consume a string for JSON parsing
  std::string json_str = fdp.ConsumeRandomLengthString(1024);

  switch (choice) {
    case 0: {
      // Fuzz json_tokener_parse
      struct json_object *obj = json_tokener_parse(json_str.c_str());
      if (obj != NULL) {
        json_object_put(obj);
      }
      break;
    }
    case 1: {
      // Fuzz json_object_from_fd_ex
      int fd = open("/dev/null", O_RDONLY);
      if (fd >= 0) {
        struct json_object *obj = json_object_from_fd_ex(fd, fdp.ConsumeIntegralInRange<int>(1, 32));
        if (obj != NULL) {
          json_object_put(obj);
        }
        close(fd);
      }
      break;
    }
    case 2: {
      // Fuzz json_object_new_string and json_object_to_json_string
      struct json_object *obj = json_object_new_string(json_str.c_str());
      if (obj != NULL) {
        const char *json_output = json_object_to_json_string(obj);
        (void)json_output; // Avoid unused variable warning
        json_object_put(obj);
      }
      break;
    }
    case 3: {
      // Fuzz json_object_new_int and json_object_get_int
      int32_t num = fdp.ConsumeIntegral<int32_t>();
      struct json_object *obj = json_object_new_int(num);
      if (obj != NULL) {
        int32_t result = json_object_get_int(obj);
        (void)result; // Avoid unused variable warning
        json_object_put(obj);
      }
      break;
    }
    case 4: {
      // Fuzz json_object_new_double and json_object_get_double
      double num = fdp.ConsumeFloatingPoint<double>();
      struct json_object *obj = json_object_new_double(num);
      if (obj != NULL) {
        double result = json_object_get_double(obj);
        (void)result; // Avoid unused variable warning
        json_object_put(obj);
      }
      break;
    }
    case 5: {
      // Fuzz json_object_new_boolean and json_object_get_boolean
      bool boolean = fdp.ConsumeBool();
      struct json_object *obj = json_object_new_boolean(boolean);
      if (obj != NULL) {
        bool result = json_object_get_boolean(obj);
        (void)result; // Avoid unused variable warning
        json_object_put(obj);
      }
      break;
    }
  }
}
