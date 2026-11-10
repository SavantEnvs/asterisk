/* Dialplan expression parser/evaluator: $[ ... ] (main/ast_expr2.y, ast_expr2.fl). */
#include "asterisk.h"
#include <stdint.h>
#include <string.h>
#include "asterisk/ast_expr.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char result[4096];
	char *expr;

	if (size > 2048) {
		return -1;
	}
	expr = ast_malloc(size + 1);
	memcpy(expr, data, size);
	expr[size] = '\0';
	ast_expr(expr, result, sizeof(result), NULL);
	ast_free(expr);
	return 0;
}
