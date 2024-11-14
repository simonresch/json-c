#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
extern "C" {
  #include "strerror_override.h"
  #include "json_util.h"
  #include "json_object.h"
  #include "json_tokener.h"
  #include "printbuf.h"
}

// One-time setup initialization
FUZZ_TEST_SETUP() {
  // No specific one-time setup required for this harness
}

// Fuzzing entry point
FUZZ_TEST(const uint8_t *data, size_t size) {
  // Initialize FuzzedDataProvider
  FuzzedDataProvider fdp(data, size);

  // Create a temporary file to use with json_object_from_fd_ex
  char filename[] = "/tmp/fuzz_jsonXXXXXX";
  int fd = mkstemp(filename);
  if (fd < 0) {
    return;
  }

  // Write fuzzer data to the temporary file
  size_t write_size = fdp.ConsumeIntegralInRange<size_t>(0, size);
  if (write(fd, data, write_size) != write_size) {
    close(fd);
    unlink(filename);
    return;
  }

  // Reset file descriptor to the beginning
  lseek(fd, 0, SEEK_SET);

  // Fuzz json_object_from_fd_ex with different depths
  int depth = fdp.ConsumeIntegralInRange<int>(0, 20); // Avoid negative values to prevent overflow
  if (depth >= 0) {
    struct json_object *jso = json_object_from_fd_ex(fd, depth);
    if (jso != NULL) {
      json_object_put(jso);
    }
  }

  // Close and remove the temporary file
  close(fd);
  unlink(filename);
}
