#include <pspkernel.h>

PSP_MODULE_INFO("rea_psp_fixture", 0, 1, 0);

volatile unsigned int rea_psp_global = 7;
const char rea_psp_marker[] = "rea-psp-source-owned-fixture";
unsigned int rea_psp_probe(void);

__attribute__((noinline)) unsigned int rea_psp_leaf(unsigned int value) {
  return value * 3u + rea_psp_global;
}

__attribute__((noinline)) unsigned int rea_psp_entry(unsigned int selector) {
  unsigned int adjusted = selector > 10u ? selector : selector + 1u;
  return rea_psp_leaf(adjusted) + rea_psp_probe();
}

int main(void) {
  return (int)rea_psp_entry(11u);
}
