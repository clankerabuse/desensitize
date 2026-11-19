/* C shim between the Rust rewrite of desens and MuPDF 1.28.
 *
 * Every MuPDF call that can longjmp is wrapped in fz_try/fz_catch here, so a
 * broken PDF becomes an error string instead of a setjmp unwind ripping
 * through Rust frames (which would be undefined behaviour).
 *
 * Linkage: libmupdf.so.28.6 (vendored from the pymupdf wheel; AGPL, see
 * rust/NOTICE.md). Version string must match exactly -- checked at compile
 * time via FZ_VERSION.
 */
#include "mupdf/fitz.h"
#include "mupdf/pdf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DS_STORE (256 << 20)

static char ds_err[512];

const char *ds_last_error(void)
{
	return ds_err;
}

fz_context *ds_new_context(void)
{
	fz_context *ctx = fz_new_context_imp(NULL, NULL, DS_STORE, FZ_VERSION);
	if (!ctx)
	{
		snprintf(ds_err, sizeof ds_err, "cannot create mupdf context");
		return NULL;
	}
	fz_try(ctx)
		fz_register_document_handlers(ctx);
	fz_catch(ctx)
	{
		fz_drop_context(ctx);
		snprintf(ds_err, sizeof ds_err, "register handlers: %s",
			fz_caught_message(ctx));
		return NULL;
	}
	return ctx;
}

void ds_drop_context(fz_context *ctx)
{
	fz_drop_context(ctx);
}

int ds_open_document(fz_context *ctx, const char *path, fz_document **out)
{
	fz_try(ctx)
		*out = fz_open_document(ctx, path);
	fz_catch(ctx)
	{
		snprintf(ds_err, sizeof ds_err, "open %s: %s", path, fz_caught_message(ctx));
		return -1;
	}
	return 0;
}

void ds_drop_document(fz_context *ctx, fz_document *doc)
{
	fz_drop_document(ctx, doc);
}

int ds_count_pages(fz_context *ctx, fz_document *doc, int *out)
{
	fz_try(ctx)
		*out = fz_count_pages(ctx, doc);
	fz_catch(ctx)
	{
		snprintf(ds_err, sizeof ds_err, "count pages: %s", fz_caught_message(ctx));
		return -1;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* Extraction (plan + verify phases; read-only on the document)        */
/* ------------------------------------------------------------------ */

int ds_extract_page(fz_context *ctx, fz_document *doc, int number,
	fz_stext_page **out)
{
	fz_stext_options opts;
	fz_stext_page *text = NULL;

	fz_var(text);

	fz_try(ctx)
	{
		fz_init_stext_options(ctx, &opts);
		/* same flags pymupdf uses for get_text(), including images:
		 * without them, an image-only scan page looks blank and the
		 * scan refusal below would fake a clean copy */
		opts.flags = FZ_STEXT_PRESERVE_LIGATURES | FZ_STEXT_PRESERVE_WHITESPACE
			| FZ_STEXT_PRESERVE_IMAGES;
		opts.scale = 1.0f;
		text = fz_new_stext_page_from_page_number(ctx, doc, number, &opts);
	}
	fz_catch(ctx)
	{
		snprintf(ds_err, sizeof ds_err, "extract page %d: %s",
			number + 1, fz_caught_message(ctx));
		return -1;
	}

	*out = text;
	return 0;
}

void ds_drop_stext_page(fz_context *ctx, fz_stext_page *p)
{
	fz_drop_stext_page(ctx, p);
}

/* ------------------------------------------------------------------ */
/* String lists (annot/widget/outline payloads handed to Rust)         */
/* ------------------------------------------------------------------ */

typedef struct
{
	char **items;
	int n;
	int cap;
} ds_str_list;

static void ds_push(ds_str_list *l, const char *s)
{
	if (l->n == l->cap)
	{
		l->cap = l->cap ? l->cap * 2 : 8;
		l->items = realloc(l->items, sizeof(char *) * l->cap);
	}
	l->items[l->n++] = strdup(s);
}

void ds_free_str_list(ds_str_list *l)
{
	int i;
	for (i = 0; i < l->n; i++)
		free(l->items[i]);
	free(l->items);
	l->items = NULL;
	l->n = l->cap = 0;
}

/* Contents at 2*i, subject at 2*i+1 -- always both slots, so annot i is
 * addressable from Rust by index. Empty strings are pushed as-is. */
int ds_annot_texts(fz_context *ctx, fz_document *doc_, int number,
	ds_str_list *out)
{
	pdf_document *doc = (pdf_document *)doc_;
	pdf_page *page = NULL;
	pdf_annot *a;

	fz_var(page);
	memset(out, 0, sizeof *out);

	fz_try(ctx)
	{
		page = pdf_load_page(ctx, doc, number);
		for (a = pdf_first_annot(ctx, page); a; a = pdf_next_annot(ctx, a))
		{
			const char *c = pdf_annot_contents(ctx, a);
			ds_push(out, c ? c : "");
			c = pdf_annot_subject(ctx, a);
			ds_push(out, c ? c : "");
		}
	}
	fz_always(ctx)
	{
		fz_drop_page(ctx, (fz_page *)page);
	}
	fz_catch(ctx)
	{
		snprintf(ds_err, sizeof ds_err, "annots page %d: %s",
			number + 1, fz_caught_message(ctx));
		return -1;
	}
	return 0;
}

int ds_set_annot_texts(fz_context *ctx, fz_document *doc_, int number,
	int idx, const char *contents, const char *subject)
{
	pdf_document *doc = (pdf_document *)doc_;
	pdf_page *page = NULL;
	pdf_annot *a;
	int i;

	fz_var(page);

	fz_try(ctx)
	{
		page = pdf_load_page(ctx, doc, number);
		a = pdf_first_annot(ctx, page);
		for (i = 0; i < idx && a; i++)
			a = pdf_next_annot(ctx, a);
		if (!a)
			fz_throw(ctx, FZ_ERROR_GENERIC, "no annot %d", idx);
		if (contents)
			pdf_set_annot_contents(ctx, a, contents);
		if (subject)
			pdf_set_annot_subject(ctx, a, subject);
		pdf_update_annot(ctx, a);
	}
	fz_always(ctx)
	{
		fz_drop_page(ctx, (fz_page *)page);
	}
	fz_catch(ctx)
	{
		snprintf(ds_err, sizeof ds_err, "set annot page %d idx %d: %s",
			number + 1, idx, fz_caught_message(ctx));
		return -1;
	}
	return 0;
}

/* One entry per widget: value (or "") then field name (or ""). */
int ds_widget_texts(fz_context *ctx, fz_document *doc_, int number,
	ds_str_list *out)
{
	pdf_document *doc = (pdf_document *)doc_;
	pdf_page *page = NULL;
	pdf_annot *w;

	fz_var(page);
	memset(out, 0, sizeof *out);

	fz_try(ctx)
	{
		page = pdf_load_page(ctx, doc, number);
		for (w = pdf_first_widget(ctx, page); w; w = pdf_next_widget(ctx, w))
		{
			const char *v = pdf_annot_field_value(ctx, w);
			ds_push(out, v ? v : "");
			v = pdf_annot_field_label(ctx, w);
			ds_push(out, v ? v : "");
		}
	}
	fz_always(ctx)
	{
		fz_drop_page(ctx, (fz_page *)page);
	}
	fz_catch(ctx)
	{
		snprintf(ds_err, sizeof ds_err, "widgets page %d: %s",
			number + 1, fz_caught_message(ctx));
		return -1;
	}
	return 0;
}

static void ds_outline_walk(fz_outline *o, ds_str_list *out)
{
	for (; o; o = o->next)
	{
		if (o->title)
			ds_push(out, o->title);
		if (o->down)
			ds_outline_walk(o->down, out);
	}
}

int ds_outline_titles(fz_context *ctx, fz_document *doc_, ds_str_list *out)
{
	pdf_document *doc = (pdf_document *)doc_;
	fz_outline *o = NULL;

	fz_var(o);
	memset(out, 0, sizeof *out);

	fz_try(ctx)
		o = pdf_load_outline(ctx, doc);
	fz_catch(ctx)
	{
		snprintf(ds_err, sizeof ds_err, "outline: %s", fz_caught_message(ctx));
		return -1;
	}
	ds_outline_walk(o, out);
	fz_drop_outline(ctx, o);
	return 0;
}

/* ------------------------------------------------------------------ */
/* Write phase: redact, scrub, save                                    */
/* ------------------------------------------------------------------ */

int ds_apply_redactions(fz_context *ctx, fz_document *doc_, int number,
	const fz_rect *rects, int n_rects, int image_method)
{
	pdf_document *doc = (pdf_document *)doc_;
	pdf_page *page = NULL;
	pdf_annot *annot = NULL;
	fz_rect crop;
	fz_matrix ctm, inv;
	int i;

	fz_var(page);
	fz_var(annot);

	fz_try(ctx)
	{
		page = pdf_load_page(ctx, doc, number);
		/* pdf_set_annot_rect takes PAGE (display) space and converts to
		 * user space itself (pdf-annot.c: inverts the page ctm) -- so the
		 * word boxes are passed through unchanged. */
		for (i = 0; i < n_rects; i++)
		{
			if (getenv("DS_DEBUG_RECTS"))
				fprintf(stderr, "p%d rect display=(%.1f %.1f %.1f %.1f)\n",
					number + 1, rects[i].x0, rects[i].y0, rects[i].x1, rects[i].y1);
			annot = pdf_create_annot(ctx, page, PDF_ANNOT_REDACT);
			pdf_set_annot_rect(ctx, annot, rects[i]);
		}
		{
			pdf_redact_options o;
			int n;
			memset(&o, 0, sizeof o);
			o.black_boxes = 0;              /* pymupdf: fill=(1,1,1), no box */
			o.image_method = image_method;  /* NONE on text pages, PIXELS on scans */
			o.line_art = PDF_REDACT_LINE_ART_NONE;
			o.text = PDF_REDACT_TEXT_REMOVE;
			n = pdf_redact_page(ctx, doc, page, &o);
			if (getenv("DS_DEBUG_RECTS"))
				fprintf(stderr, "p%d pdf_redact_page -> %d\n", number + 1, n);
		}
	}
	fz_always(ctx)
	{
		fz_drop_page(ctx, (fz_page *)page);
	}
	fz_catch(ctx)
	{
		snprintf(ds_err, sizeof ds_err, "redact page %d: %s",
			number + 1, fz_caught_message(ctx));
		return -1;
	}
	return 0;
}

int ds_scrub_metadata(fz_context *ctx, fz_document *doc)
{
	static const char *keys[] = {
		"info:Title", "info:Author", "info:Subject",
		"info:Keywords", "info:Creator", "info:Producer",
	};
	int i;
	fz_try(ctx)
		for (i = 0; i < 6; i++)
			fz_set_metadata(ctx, doc, keys[i], "");
	fz_catch(ctx)
	{
		snprintf(ds_err, sizeof ds_err, "scrub metadata: %s",
			fz_caught_message(ctx));
		return -1;
	}
	return 0;
}

int ds_save_document(fz_context *ctx, fz_document *doc_, const char *path)
{
	pdf_document *doc = (pdf_document *)doc_;
	pdf_write_options opts;

	/* mirrors the Python tool's save(garbage=4, deflate=True, clean=True) */
	memset(&opts, 0, sizeof opts);
	opts.do_garbage = 4;
	opts.do_compress = 1;
	opts.do_clean = 1;

	fz_try(ctx)
		pdf_save_document(ctx, doc, path, &opts);
	fz_catch(ctx)
	{
		snprintf(ds_err, sizeof ds_err, "save %s: %s",
			path, fz_caught_message(ctx));
		return -1;
	}
	return 0;
}
