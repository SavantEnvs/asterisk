/* Asterisk .conf parser (main/config.c): categories, templates, #include, variable lines. */
#include "asterisk.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "asterisk/config.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct ast_flags flags = { CONFIG_FLAG_NOCACHE | CONFIG_FLAG_NOREALTIME };
	const char *tmpdir = getenv("TMPDIR");
	char path[256];
	struct ast_config *cfg;
	const char *cat = NULL;
	int fd;

	snprintf(path, sizeof(path), "%s/fuzz_config.XXXXXX", tmpdir && *tmpdir ? tmpdir : "/tmp");
	fd = mkstemp(path);
	if (fd < 0) {
		return -1;
	}
	if ((size_t) write(fd, data, size) != size) {
		close(fd);
		unlink(path);
		return -1;
	}
	close(fd);

	cfg = ast_config_load2(path, "fuzz_config", flags);
	if (cfg && cfg != CONFIG_STATUS_FILEMISSING && cfg != CONFIG_STATUS_FILEINVALID
		&& cfg != CONFIG_STATUS_FILEUNCHANGED) {
		while ((cat = ast_category_browse(cfg, cat))) {
			struct ast_variable *var = ast_variable_browse(cfg, cat);
			for (; var; var = var->next) {
				(void) ast_variable_retrieve(cfg, cat, var->name);
			}
		}
		ast_config_destroy(cfg);
	}
	unlink(path);
	return 0;
}
