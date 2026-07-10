#include <stddef.h>
#include <limits.h>
#include <assert.h>
#include <stdio.h>

/* Inline copy of the guard helper from vm.c — keeps this test self-contained. */
static int
uc_string_concat_would_overflow(size_t l1, size_t l2)
{
	return l2 >= SIZE_MAX - l1;
}

int main(void)
{
	/* safe cases */
	assert(!uc_string_concat_would_overflow(0, 0));
	assert(!uc_string_concat_would_overflow(1, 1));
	assert(!uc_string_concat_would_overflow(SIZE_MAX / 2, SIZE_MAX / 2 - 1));

	/* boundary: l1 + l2 == SIZE_MAX - 1, safe */
	assert(!uc_string_concat_would_overflow(1, SIZE_MAX - 2));

	/* boundary: l1 + l2 == SIZE_MAX exactly — must be rejected (off-by-one case)
	 * Without the >= fix, l1+l2+1 wraps to 0 and the tiny stack-buffer branch
	 * is taken, overflowing an 8-byte buf with SIZE_MAX bytes of data. */
	assert(uc_string_concat_would_overflow(SIZE_MAX / 2, SIZE_MAX - SIZE_MAX / 2));
	assert(uc_string_concat_would_overflow(1, SIZE_MAX - 1));

	/* clearly overflowing cases */
	assert(uc_string_concat_would_overflow(SIZE_MAX, 1));
	assert(uc_string_concat_would_overflow(SIZE_MAX, SIZE_MAX));

	/* incremental-accumulation pattern: one large string plus a small chunk */
	assert(uc_string_concat_would_overflow(SIZE_MAX - 1, 1));
	assert(uc_string_concat_would_overflow(SIZE_MAX - 1, 2));

	printf("All overflow guard tests passed.\n");
	return 0;
}
