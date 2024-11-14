#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
extern "C" {
  #include "strerror_override.h"
  #include "debug.h"
  #include "json_object.h"
  #include "json_tokener.h"
  #include "json_util.h"
  #include "printbuf.h"
}

FUZZ_TEST_SETUP() {
  // One time initialization tasks, e.g., memory allocation, file opening.
}

FUZZ_TEST(const uint8_t *data, size_t size) {
  // Initialize FuzzedDataProvider with input data
  FuzzedDataProvider fdp(data, size);

  // Create a temporary file to use with json_object_from_fd
  char temp_filename[] = "/tmp/fuzz_json_utilXXXXXX";
  int temp_fd = mkstemp(temp_filename);
  if (temp_fd == -1) {
    return;
  }

  // Write fuzzer data to the temporary file
  write(temp_fd, data, size);
  lseek(temp_fd, 0, SEEK_SET);

  // Call json_object_from_fd with the temporary file descriptor
  struct json_object *json_obj = json_object_from_fd(temp_fd);
  if (json_obj != NULL) {
    json_object_put(json_obj);
  }

  // Close and remove the temporary file
  close(temp_fd);
  unlink(temp_filename);

  // Create a temporary file to use with json_object_to_file_ext
  char temp_outfile[] = "/tmp/fuzz_json_util_outXXXXXX";
  int temp_out_fd = mkstemp(temp_outfile);
  if (temp_out_fd == -1) {
    return;
  }

  // Create a json_object from the fuzzer data
  struct json_object *jso = json_tokener_parse(fdp.ConsumeRemainingBytesAsString().c_str());
  if (jso != NULL) {
    // Write the json_object to the temporary file
    json_object_to_fd(temp_out_fd, jso, JSON_C_TO_STRING_PRETTY);
    json_object_put(jso);
  }

  // Close and remove the temporary output file
  close(temp_out_fd);
  unlink(temp_outfile);
}
