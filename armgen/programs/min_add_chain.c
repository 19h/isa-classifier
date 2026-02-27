/*
 * Minimal Integer Addition Chain
 *
 * Generates sequences dominated by integer ADD instructions.
 * Useful for ISA detection training - creates distinctive ADD patterns.
 *
 * Expected dominant instructions by architecture:
 *   x86:    add, lea
 *   ARM:    add, adds
 *   RISC-V: add, addi
 *   MIPS:   addu, addiu
 *   PPC:    add, addi
 */

volatile int sink;

int main(void) {
    register int a = 1, b = 2, c = 3, d = 4;
    register int e = 5, f = 6, g = 7, h = 8;

    for (int i = 0; i < 100000; i++) {
        /* Chain of dependent additions */
        a = a + b;
        b = b + c;
        c = c + d;
        d = d + a;

        e = e + f;
        f = f + g;
        g = g + h;
        h = h + e;

        /* Cross-chain additions */
        a = a + e;
        b = b + f;
        c = c + g;
        d = d + h;

        /* More additions to increase density */
        e = e + a + 1;
        f = f + b + 2;
        g = g + c + 3;
        h = h + d + 4;
    }

    sink = a + b + c + d + e + f + g + h;
    return 0;
}
