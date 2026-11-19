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

/* ------------------------------------------------------------------ */
/* Rendering for OCR (milestone 2)                                    */
/* ------------------------------------------------------------------ */

int ds_render_png(fz_context *ctx, fz_document *doc, int number, double dpi,
	int delta_deg, const fz_rect *clip_or_null, int gray,
	const char *out_path, fz_matrix *out_ctm)
{
	fz_page *page = NULL;
	fz_pixmap *pix = NULL;
	fz_device *dev = NULL;
	fz_matrix ctm;
	fz_rect bounds, tb;
	fz_irect ibox;
	double s = dpi / 72.0;

	fz_var(page);
	fz_var(pix);
	fz_var(dev);

	fz_try(ctx)
	{
		page = fz_load_page(ctx, doc, number);
		bounds = fz_bound_page(ctx, page);
		if (clip_or_null)
		{
			fz_rect clip = *clip_or_null;
			bounds = fz_intersect_rect(bounds, clip);
		}

		/* display -> render: scale, then rotate by delta (pymupdf
		 * set_rotation equivalent), then translate into view */
		ctm = fz_concat(fz_scale(s, s), fz_rotate(delta_deg));
		tb = fz_transform_rect(bounds, ctm);
		ctm = fz_concat(ctm, fz_translate(-tb.x0, -tb.y0));

		ibox = fz_irect_from_rect(fz_transform_rect(bounds, ctm));
		pix = fz_new_pixmap_with_bbox(ctx,
			gray ? fz_device_gray(ctx) : fz_device_rgb(ctx), ibox, NULL, 0);
		fz_clear_pixmap_with_value(ctx, pix, 255);
		dev = fz_new_draw_device(ctx, fz_identity, pix);
		fz_run_page(ctx, page, dev, ctm, NULL);
		fz_close_device(ctx, dev);
		fz_save_pixmap_as_png(ctx, pix, out_path);
	}
	fz_always(ctx)
	{
		fz_drop_device(ctx, dev);
		fz_drop_pixmap(ctx, pix);
		fz_drop_page(ctx, page);
	}
	fz_catch(ctx)
	{
		snprintf(ds_err, sizeof ds_err, "render page %d: %s",
			number + 1, fz_caught_message(ctx));
		return -1;
	}

	if (out_ctm)
		*out_ctm = ctm;
	return 0;
}

double ds_page_ink_fraction(fz_context *ctx, fz_document *doc, int number)
{
	fz_page *page = NULL;
	fz_pixmap *pix = NULL;
	fz_device *dev = NULL;
	double frac = 1.0;
	size_t i, n;

	fz_var(page);
	fz_var(pix);
	fz_var(dev);

	fz_try(ctx)
	{
		page = fz_load_page(ctx, doc, number);
		pix = fz_new_pixmap_with_bbox(ctx, fz_device_gray(ctx),
			fz_irect_from_rect(fz_bound_page(ctx, page)), NULL, 0);
		fz_clear_pixmap_with_value(ctx, pix, 255);
		dev = fz_new_draw_device(ctx, fz_identity, pix);
		fz_run_page(ctx, page, dev, fz_identity, NULL);
		fz_close_device(ctx, dev);
		n = (size_t)pix->w * pix->h * pix->n;
		{
			unsigned char *samples = pix->samples;
			size_t ink = 0;
			for (i = 0; i < n; i++)
				if (samples[i] < 200)
					ink++;
			frac = n ? (double)ink / (double)n : 1.0;
		}
	}
	fz_always(ctx)
	{
		fz_drop_device(ctx, dev);
		fz_drop_pixmap(ctx, pix);
		fz_drop_page(ctx, page);
	}
	fz_catch(ctx)
	{
		/* unknown: assume there is something to read (python parity) */
		return 1.0;
	}
	return frac;
}

/* ------------------------------------------------------------------ */
/* Writing text ops: visible placeholders + invisible OCR text layer   */
/* ------------------------------------------------------------------ */

typedef struct
{
	float x, y;        /* display space, baseline origin */
	float size;
	float r, g, b;
	int render_mode;   /* 0 visible, 3 invisible */
	const char *text;  /* latin-1-ish; other chars become '?' */
} ds_text_op;

static void ds_escape_tj(fz_context *ctx, fz_buffer *buf, const char *text)
{
	for (; *text; text++)
	{
		unsigned char c = (unsigned char)*text;
		if (c == '\\' || c == '(' || c == ')')
			fz_append_byte(ctx, buf, '\\');
		if (c >= 32 && c < 127)
			fz_append_byte(ctx, buf, c);
		else if (c >= 160)
			fz_append_byte(ctx, buf, c); /* latin-1 bytes pass through */
		else
			fz_append_byte(ctx, buf, '?');
	}
}

int ds_write_text_ops(fz_context *ctx, fz_document *doc_, int number,
	const ds_text_op *ops, int n_ops)
{
	pdf_document *doc = (pdf_document *)doc_;
	pdf_obj *pageobj = NULL;
	pdf_obj *res = NULL, *fontdict = NULL, *font = NULL, *f1 = NULL;
	pdf_obj *contents = NULL, *newstream = NULL;
	fz_buffer *buf = NULL;
	fz_matrix ctm, inv;
	fz_rect crop;
	int i;

	if (n_ops <= 0)
		return 0;

	fz_var(res);
	fz_var(fontdict);
	fz_var(font);
	fz_var(contents);
	fz_var(newstream);
	fz_var(buf);

	fz_try(ctx)
	{
		pageobj = pdf_lookup_page_obj(ctx, doc, number);

		/* display -> user space, same as the annot rect conversion */
		{
			pdf_page *pp = pdf_load_page(ctx, doc, number);
			pdf_page_transform(ctx, pp, &crop, &ctm);
			fz_drop_page(ctx, (fz_page *)pp);
		}
		inv = fz_invert_matrix(ctm);

		res = pdf_dict_gets(ctx, pageobj, "Resources");
		if (!res)
		{
			res = pdf_add_object(ctx, doc, pdf_new_dict(ctx, doc, 4));
			pdf_dict_puts(ctx, pageobj, "Resources", res);
		}
		fontdict = pdf_dict_gets(ctx, res, "Font");
		if (!fontdict)
		{
			fontdict = pdf_add_object(ctx, doc, pdf_new_dict(ctx, doc, 4));
			pdf_dict_puts(ctx, res, "Font", fontdict);
		}
		f1 = pdf_dict_gets(ctx, fontdict, "F1");
		if (!f1)
		{
			font = pdf_new_dict(ctx, doc, 4);
			pdf_dict_puts(ctx, font, "Type", PDF_NAME(Font));
			pdf_dict_puts(ctx, font, "Subtype", PDF_NAME(Type1));
			pdf_dict_put_name(ctx, font, PDF_NAME(BaseFont), "Helvetica");
			f1 = pdf_add_object(ctx, doc, font);
			pdf_dict_puts(ctx, fontdict, "F1", f1);
		}

		buf = fz_new_buffer(ctx, 256);
		for (i = 0; i < n_ops; i++)
		{
			/* display baseline point -> user space for the Tm */
			fz_point p;
			p.x = ops[i].x;
			p.y = ops[i].y;
			p = fz_transform_point(p, inv);
			fz_append_printf(ctx, buf, "q BT %d Tr /F1 %g Tf %g %g %g rg 1 0 0 1 %g %g Tm (",
				ops[i].render_mode, ops[i].size,
				ops[i].r, ops[i].g, ops[i].b, p.x, p.y);
			ds_escape_tj(ctx, buf, ops[i].text);
			fz_append_printf(ctx, buf, ") Tj ET Q\n");
		}
		newstream = pdf_add_stream(ctx, doc, buf, NULL, 1);

		contents = pdf_dict_gets(ctx, pageobj, "Contents");
		if (!contents)
			pdf_dict_puts(ctx, pageobj, "Contents", newstream);
		else if (pdf_is_array(ctx, contents))
			pdf_array_push(ctx, contents, newstream);
		else
		{
			pdf_obj *arr = pdf_add_object(ctx, doc, pdf_new_array(ctx, doc, 4));
			pdf_array_push(ctx, arr, contents);
			pdf_array_push(ctx, arr, newstream);
			pdf_dict_puts(ctx, pageobj, "Contents", arr);
		}
	}
	fz_always(ctx)
	{
		fz_drop_buffer(ctx, buf);
	}
	fz_catch(ctx)
	{
		snprintf(ds_err, sizeof ds_err, "write text ops page %d: %s",
			number + 1, fz_caught_message(ctx));
		return -1;
	}
	return 0;
}

/* Rewrite one form widget's value by index (python widget.field_value=...). */
int ds_set_widget_value(fz_context *ctx, fz_document *doc_, int number,
	int idx, const char *value)
{
	pdf_document *doc = (pdf_document *)doc_;
	pdf_page *page = NULL;
	pdf_annot *w;
	int i;

	fz_var(page);

	fz_try(ctx)
	{
		page = pdf_load_page(ctx, doc, number);
		w = pdf_first_widget(ctx, page);
		for (i = 0; i < idx && w; i++)
			w = pdf_next_widget(ctx, w);
		if (!w)
			fz_throw(ctx, FZ_ERROR_GENERIC, "no widget %d", idx);
		pdf_set_field_value(ctx, doc, pdf_annot_obj(ctx, w), value, 1);
		pdf_update_annot(ctx, w);
	}
	fz_always(ctx)
	{
		fz_drop_page(ctx, (fz_page *)page);
	}
	fz_catch(ctx)
	{
		snprintf(ds_err, sizeof ds_err, "set widget page %d idx %d: %s",
			number + 1, idx, fz_caught_message(ctx));
		return -1;
	}
	return 0;
}
