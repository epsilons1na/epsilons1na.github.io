#include <stdio.h>
#include <unistd.h>

int main() {
  printf("stderr :%p\n", stderr);
  read(STDIN_FILENO, stderr, 0x100);
}
