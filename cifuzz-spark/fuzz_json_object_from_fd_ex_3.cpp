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
extern "C" {
  #include "strerror_override.h"
  #include "json_object.h"
  #include "json_tokener.h"
  #include "json_util.h"
  #include "printbuf.h"
}

// FUZZ_TEST_SETUP: One-time initialization tasks.
FUZZ_TEST_SETUP() {
  // No specific setup required for this harness.
}

// FUZZ_TEST: Entry point for the fuzzing harness.
FUZZ_TEST(const uint8_t *data, size_t size) {
  // Initialize FuzzedDataProvider to generate fuzzed inputs.
  FuzzedDataProvider fdp(data, size);

  // Fuzzing json_object_from_fd_ex
  int temp_fd = open("/dev/null", O_RDONLY);
  if (temp_fd < 0) {
    return; // Exit if unable to open the file descriptor.
  }
  int depth = fdp.ConsumeIntegralInRange<int>(1, 20); // Fix the depth range to avoid invalid values.
  struct json_object *jso = json_object_from_fd_ex(temp_fd, depth);
  if (jso != NULL) {
    json_object_put(jso);
  }
  close(temp_fd);

  // Fuzzing json_object_from_file
  std::string filename = "/tmp/fuzz_json_file";
  FILE *temp_file = fopen(filename.c_str(), "wb");
  if (temp_file) {
    std::string file_content = fdp.ConsumeRemainingBytesAsString();
    fwrite(file_content.c_str(), 1, file_content.size(), temp_file);
    fclose(temp_file);

    struct json_object *jo = json_object_from_file(filename.c_str());
    if (jo != NULL) {
      json_object_put(jo);
    }
    remove(filename.c_str()); // Clean up the temporary file.
  }

  // Fuzzing json_object_to_file_ext
  struct json_object *json_obj = json_tokener_parse(fdp.ConsumeRemainingBytesAsString().c_str());
  if (json_obj != NULL) {
    std::string out_filename = "/tmp/fuzz_json_out_file";
    int flags = fdp.ConsumeIntegral<int>();
    json_object_to_file_ext(out_filename.c_str(), json_obj, flags);
    json_object_put(json_obj);
    remove(out_filename.c_str()); // Clean up the temporary file.
  }
}
