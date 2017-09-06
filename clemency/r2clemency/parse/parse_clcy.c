/* radare - LGPL - Copyright 2017 - MaskRay */
#include <r_asm.h>
#include <r_core.h>
#include <r_lib.h>
#include <r_parse.h>
#include <r_reg.h>
#include <r_types.h>
#include <r_util.h>

#include "../include/disasm.h"

static int _parse(RParse *p, const char *src, char *dst) {
	RCore *core = p->user;
	RAsmOp op;
	diassemble (core->assembler, &op, src, strlen (src));
	strcpy (src, dst);
	return true;
}

static bool _varsub(RParse *p, RAnalFunction *f, ut64 addr, int oplen, char *src, char *dst, int len) {
	RList *spargs = NULL, *bpargs = NULL, *regargs = NULL;
	RListIter *iter;
	RAnalVar *var;
	char *str = strdup (src), *sub, *replace;
	bool ret = true;
	if (!str) {
		goto err;
	}
	if (p->relsub) {
		// TODO Support asm.relsub
	}

	regargs = p->varlist (p->anal, f, 'r');
	bpargs = p->varlist (p->anal, f, 'b');
	spargs = p->varlist (p->anal, f, 's');

	// Stack register variable st+%#x
	r_list_foreach (bpargs, iter, var) {
		if (var->delta >= 0) {
			sub = r_str_newf ("[st+%#x", var->delta);
		} else {
			sub = r_str_newf ("[st-%#x", -var->delta);
		}
		if (!sub) {
			goto err;
		}
		if (strstr (str, sub)) {
			replace = r_str_newf ("[st %c %s", var->delta >= 0 ? '+' : '-', var->name);
			str = r_str_replace (str, sub, replace, 0);
			free (replace);
		}
		free (sub);
	}

	// Frame register variable r28+%#x
	r_list_foreach (bpargs, iter, var) {
		if (var->delta >= 0) {
			sub = r_str_newf ("[r28+%#x", var->delta);
		} else {
			sub = r_str_newf ("[r28-%#x", -var->delta);
		}
		if (!sub) {
			goto err;
		}
		if (strstr (str, sub)) {
			replace = r_str_newf ("[r28 %c %s", var->delta >= 0 ? '+' : '-', var->name);
			str = r_str_replace (str, sub, replace, 0);
			free (replace);
		}
		free (sub);
	}

	r_list_foreach (regargs, iter, var) {
		RRegItem *r = r_reg_index_get (p->anal->reg, var->delta);
		if (r && r->name && strstr (str, r->name)) {
			str = r_str_replace (str, r->name, var->name, 1);
		}
	}

	if (strlen (str) >= len) {
		goto err;
	}
	r_str_ncpy (dst, str, len);

 out:
	r_list_free (spargs);
	r_list_free (bpargs);
	r_list_free (regargs);
	free (str);
	return ret;

 err:
	ret = false;
	goto out;
}

RParsePlugin r_parse_plugin_clcy = {
	.name = "clcy",
	.desc = "cLEMENCy pseudo syntax",
	.parse = &_parse,
	.varsub = &_varsub,
};

RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_PARSE,
	.data = &r_parse_plugin_clcy,
	.version = R2_VERSION,
};
