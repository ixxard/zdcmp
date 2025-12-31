void xor_swap(int *a, int *b) {
    if (a != b) { // Important check for same memory location!
        *a = *a ^ *b;
        *b = *a ^ *b;
        *a = *a ^ *b;
    }
}
