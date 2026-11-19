//! Hand-rolled FFI to MuPDF 1.28 via the C shim (src/shim.c).
//!
//! Every MuPDF call that can longjmp lives behind the shim (fz_try/fz_catch),
//! so a broken PDF is an Err(...) instead of undefined behaviour. The only
//! MuPDF memory touched directly from Rust is the finished stext tree, walked
//! by pointer chasing -- no throwing calls inside the walk.
//!
//! Threading: one fz_context per thread (contexts built with NULL locks are
//! single-threaded; independent contexts per thread are the documented safe
//! pattern). Rayon workers each get their own on first use.

use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};

use anyhow::{anyhow, Context, Result};

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct FzRect {
    pub x0: f32,
    pub y0: f32,
    pub x1: f32,
    pub y1: f32,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct FzPoint {
    pub x: f32,
    pub y: f32,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct FzQuad {
    pub ul: FzPoint,
    pub ur: FzPoint,
    pub ll: FzPoint,
    pub lr: FzPoint,
}

/// Mirror of `struct fz_stext_char` (mupdf/fitz/structured-text.h, 1.28).
#[repr(C)]
pub struct FzStextChar {
    pub c: c_int,
    pub bidi: u16,
    pub flags: u16,
    pub argb: u32,
    pub origin: FzPoint,
    pub quad: FzQuad,
    pub size: f32,
    pub font: *mut c_void,
    pub next: *mut FzStextChar,
}

/// Mirror of `struct fz_stext_line`.
#[repr(C)]
pub struct FzStextLine {
    pub wmode: u8,
    pub flags: u8,
    pub dir: FzPoint,
    pub bbox: FzRect,
    pub first_char: *mut FzStextChar,
    pub last_char: *mut FzStextChar,
    pub prev: *mut FzStextLine,
    pub next: *mut FzStextLine,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct FzBlockText {
    pub first_line: *mut FzStextLine,
    pub last_line: *mut FzStextLine,
    pub flags: c_int,
}

/// The block union is 32 bytes in C (matrix+image wins); keep the size honest.
#[repr(C)]
pub union FzStextBlockU {
    pub t: FzBlockText,
    pub force_size: [u8; 32],
}

/// Mirror of `struct fz_stext_block` (prev/next sit *after* the union).
#[repr(C)]
pub struct FzStextBlock {
    pub type_: c_int,
    pub id: c_int,
    pub bbox: FzRect,
    pub u: FzStextBlockU,
    pub prev: *mut FzStextBlock,
    pub next: *mut FzStextBlock,
}

/// Mirror of `struct fz_stext_page` (we only walk `first_block`).
#[repr(C)]
pub struct FzStextPage {
    pub refs: c_int,
    pub pool: *mut c_void,
    pub mediabox: FzRect,
    pub first_block: *mut FzStextBlock,
    pub last_block: *mut FzStextBlock,
    pub last_struct: *mut c_void,
    pub id_list: *mut c_void,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct DsStrList {
    pub items: *mut *mut c_char,
    pub n: c_int,
    pub cap: c_int,
}

pub const FZ_STEXT_BLOCK_TEXT: c_int = 0;
pub const FZ_STEXT_BLOCK_IMAGE: c_int = 1;

/// image redaction methods (mupdf/pdf/page.h)
pub const PDF_REDACT_IMAGE_NONE: c_int = 0;
pub const PDF_REDACT_IMAGE_PIXELS: c_int = 2;

extern "C" {
    fn ds_last_error() -> *const c_char;
    fn ds_new_context() -> *mut c_void;
    fn ds_drop_context(ctx: *mut c_void);
    fn ds_open_document(ctx: *mut c_void, path: *const c_char, out: *mut *mut c_void) -> c_int;
    fn ds_drop_document(ctx: *mut c_void, doc: *mut c_void);
    fn ds_count_pages(ctx: *mut c_void, doc: *mut c_void, out: *mut c_int) -> c_int;
    fn ds_extract_page(
        ctx: *mut c_void,
        doc: *mut c_void,
        number: c_int,
        out: *mut *mut FzStextPage,
    ) -> c_int;
    fn ds_drop_stext_page(ctx: *mut c_void, page: *mut FzStextPage);
    fn ds_apply_redactions(
        ctx: *mut c_void,
        doc: *mut c_void,
        number: c_int,
        rects: *const FzRect,
        n_rects: c_int,
        image_method: c_int,
    ) -> c_int;
    fn ds_scrub_metadata(ctx: *mut c_void, doc: *mut c_void) -> c_int;
    fn ds_save_document(ctx: *mut c_void, doc: *mut c_void, path: *const c_char) -> c_int;
    fn ds_annot_texts(
        ctx: *mut c_void,
        doc: *mut c_void,
        number: c_int,
        out: *mut DsStrList,
    ) -> c_int;
    fn ds_set_annot_texts(
        ctx: *mut c_void,
        doc: *mut c_void,
        number: c_int,
        idx: c_int,
        contents: *const c_char,
        subject: *const c_char,
    ) -> c_int;
    fn ds_widget_texts(
        ctx: *mut c_void,
        doc: *mut c_void,
        number: c_int,
        out: *mut DsStrList,
    ) -> c_int;
    fn ds_outline_titles(ctx: *mut c_void, doc: *mut c_void, out: *mut DsStrList) -> c_int;
    fn ds_free_str_list(l: *mut DsStrList);
}

fn mupdf_msg() -> String {
    unsafe {
        let p = ds_last_error();
        if p.is_null() {
            "unknown mupdf error".to_string()
        } else {
            CStr::from_ptr(p).to_string_lossy().into_owned()
        }
    }
}

fn bail<T>(what: &str) -> Result<T> {
    Err(anyhow!("mupdf: {what}: {}", mupdf_msg()))
}

struct CtxPtr(*mut c_void);
impl Drop for CtxPtr {
    fn drop(&mut self) {
        unsafe { ds_drop_context(self.0) };
    }
}

thread_local! {
    static CTX: RefCell<Option<CtxPtr>> = const { RefCell::new(None) };
}

/// Run `f` with this thread's fz_context, creating it on first use.
fn with_ctx<R>(f: impl FnOnce(*mut c_void) -> R) -> R {
    CTX.with(|slot| {
        let mut guard = slot.borrow_mut();
        let ctx = guard
            .get_or_insert_with(|| {
                let p = unsafe { ds_new_context() };
                if p.is_null() {
                    panic!("mupdf context init failed: {}", mupdf_msg());
                }
                CtxPtr(p)
            })
            .0;
        f(ctx)
    })
}

/// One word with its display-space box, in the same tuple shape the Python
/// tool used for `page.get_text("words")`: (x0,y0,x1,y1,text,block,line,no)
/// plus tesseract confidence as field 8 (100.0 for native text).
#[derive(Clone, Debug)]
pub struct Word {
    pub x0: f32,
    pub y0: f32,
    pub x1: f32,
    pub y1: f32,
    pub text: String,
    pub block: i32,
    pub line: i32,
    pub no: i32,
    pub conf: f32,
}

impl Word {
    fn native(x0: f32, y0: f32, x1: f32, y1: f32, text: String, block: i32, line: i32, no: i32) -> Self {
        Word { x0, y0, x1, y1, text, block, line, no, conf: 100.0 }
    }
}

pub struct PageExtract {
    pub words: Vec<Word>,
    /// whole-page plain text (feeds the verify source-vocabulary)
    pub text: String,
    /// embedded-image blocks on the page (milestone-1 caveat: not OCR-proven)
    pub image_blocks: i32,
}

struct DocHandle {
    ctx: *mut c_void,
    doc: *mut c_void,
}

impl Drop for DocHandle {
    fn drop(&mut self) {
        unsafe { ds_drop_document(self.ctx, self.doc) };
    }
}

// Per-thread cache of open read-only document handles, keyed by path.
// Rayon workers each keep one fz_context and (at most) one open document per
// file instead of re-opening the xref for every page task.
thread_local! {
    static DOC_CACHE: RefCell<std::collections::HashMap<String, DocHandle>> =
        RefCell::new(std::collections::HashMap::new());
}

fn open_doc(ctx: *mut c_void, path: &str) -> Result<DocHandle> {
    let cpath = CString::new(path).context("path contains NUL")?;
    let mut doc: *mut c_void = std::ptr::null_mut();
    let rc = unsafe { ds_open_document(ctx, cpath.as_ptr(), &mut doc) };
    if rc != 0 {
        return bail("open document");
    }
    Ok(DocHandle { ctx, doc })
}

/// Cached read-only handle for this thread: (ctx, doc). The DOC_CACHE owns
/// the DocHandle; the pair is only used on this thread while the ctx is alive.
fn cached_doc(path: &str) -> Result<(*mut c_void, *mut c_void)> {
    DOC_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some(entry) = cache.get(path) {
            return Ok((entry.ctx, entry.doc));
        }
        let handle = with_ctx(|ctx| open_doc(ctx, path))?;
        let pair = (handle.ctx, handle.doc);
        cache.insert(path.to_string(), handle);
        Ok(pair)
    })
}

fn str_list_to_vec(l: &mut DsStrList) -> Vec<String> {
    let mut out = Vec::new();
    unsafe {
        for i in 0..l.n as usize {
            let p = *l.items.add(i);
            if !p.is_null() {
                out.push(CStr::from_ptr(p).to_string_lossy().into_owned());
            } else {
                out.push(String::new());
            }
        }
        ds_free_str_list(l);
    }
    out
}

/// Extract one page's words (read-only). Opens its own document handle: safe
/// to call from many threads for the same file.
pub fn extract_page(path: &str, page: i32) -> Result<PageExtract> {
    let (ctx, doc) = cached_doc(path)?;
    let mut stext: *mut FzStextPage = std::ptr::null_mut();
    let rc = unsafe { ds_extract_page(ctx, doc, page, &mut stext) };
    if rc != 0 {
        return bail("extract");
    }

    let mut words: Vec<Word> = Vec::new();
    let mut text = String::new();
    let mut image_blocks = 0i32;

    struct CurWord {
        x0: f32,
        y0: f32,
        x1: f32,
        y1: f32,
        buf: String,
    }

        unsafe {
            let mut block_no = 0i32;
            let mut bp = (*stext).first_block;
            while !bp.is_null() {
                let b: &FzStextBlock = &*bp;
                if b.type_ == FZ_STEXT_BLOCK_TEXT {
                    let mut line_no = 0i32;
                    let mut lp = b.u.t.first_line;
                    while !lp.is_null() {
                        let line: &FzStextLine = &*lp;
                        let mut word_no = 0i32;
                        let mut cur: Option<CurWord> = None;
                        let mut line_text = String::new();
                        let mut cp = line.first_char;
                        while !cp.is_null() {
                            let ch: &FzStextChar = &*cp;
                            if ch.c == 32 {
                                // the stext device emits space chars between
                                // words (synthetic when gaps are wide)
                                if let Some(w) = cur.take() {
                                    words.push(Word::native(w.x0, w.y0, w.x1, w.y1, w.buf, block_no, line_no, word_no));
                                    word_no += 1;
                                }
                            } else {
                                let c = char::from_u32(ch.c as u32).unwrap_or('\u{FFFD}');
                                line_text.push(c);
                                let q = ch.quad;
                                let x0 = q.ul.x.min(q.ll.x).min(q.ur.x).min(q.lr.x);
                                let y0 = q.ul.y.min(q.ll.y).min(q.ur.y).min(q.lr.y);
                                let x1 = q.ul.x.max(q.ll.x).max(q.ur.x).max(q.lr.x);
                                let y1 = q.ul.y.max(q.ll.y).max(q.ur.y).max(q.lr.y);
                                match cur.as_mut() {
                                    Some(w) => {
                                        w.x0 = w.x0.min(x0);
                                        w.y0 = w.y0.min(y0);
                                        w.x1 = w.x1.max(x1);
                                        w.y1 = w.y1.max(y1);
                                        w.buf.push(c);
                                    }
                                    None => {
                                        cur = Some(CurWord { x0, y0, x1, y1, buf: c.to_string() });
                                    }
                                }
                            }
                            cp = ch.next;
                        }
                        if let Some(w) = cur.take() {
                            words.push(Word::native(w.x0, w.y0, w.x1, w.y1, w.buf, block_no, line_no, word_no));
                        }
                        text.push_str(&line_text);
                        text.push('\n');
                        line_no += 1;
                        lp = line.next;
                    }
                    text.push('\n');
                } else {
                    if b.type_ == FZ_STEXT_BLOCK_IMAGE {
                        image_blocks += 1;
                    }
                }
                block_no += 1;
                bp = b.next;
            }
            ds_drop_stext_page(ctx, stext);
        }
    Ok(PageExtract { words, text, image_blocks })
}
/// How many pages does this PDF have? (cheap enough to open for)
pub fn count_pages(path: &str) -> Result<i32> {
    with_ctx(|ctx| {
        let handle = open_doc(ctx, path)?;
        let mut n: c_int = 0;
        let rc = unsafe { ds_count_pages(ctx, handle.doc, &mut n) };
        if rc != 0 {
            return bail("count pages");
        }
        Ok(n)
    })
}

/// Write-phase handle: everything that mutates the document. One at a time,
/// single thread -- MuPDF page redaction is not worth the locking trouble,
/// and it is the fast C part anyway.
pub struct WriteDoc {
    ctx: *mut c_void,
    doc: *mut c_void,
}

impl WriteDoc {
    pub fn open(path: &str) -> Result<WriteDoc> {
        with_ctx(|ctx| {
            let cpath = CString::new(path).context("path contains NUL")?;
            let mut doc: *mut c_void = std::ptr::null_mut();
            let rc = unsafe { ds_open_document(ctx, cpath.as_ptr(), &mut doc) };
            if rc != 0 {
                bail("open document")
            } else {
                Ok(WriteDoc { ctx, doc })
            }
        })
    }

    pub fn count_pages(&self) -> Result<i32> {
        let mut n: c_int = 0;
        let rc = unsafe { ds_count_pages(self.ctx, self.doc, &mut n) };
        if rc != 0 {
            return bail("count pages");
        }
        Ok(n)
    }

    /// Burn `rects` (display space) into page `number` by deleting the glyphs
    /// under them (and optionally smearing image pixels for scans).
    pub fn apply_redactions(&self, number: i32, rects: &[FzRect], smear_images: bool) -> Result<()> {
        let method = if smear_images { PDF_REDACT_IMAGE_PIXELS } else { PDF_REDACT_IMAGE_NONE };
        let rc = unsafe {
            ds_apply_redactions(self.ctx, self.doc, number, rects.as_ptr(), rects.len() as c_int, method)
        };
        if rc != 0 {
            return bail("apply redactions");
        }
        Ok(())
    }

    pub fn scrub_metadata(&self) -> Result<()> {
        let rc = unsafe { ds_scrub_metadata(self.ctx, self.doc) };
        if rc != 0 {
            return bail("scrub metadata");
        }
        Ok(())
    }

    pub fn save(&self, path: &str) -> Result<()> {
        let cpath = CString::new(path).context("path contains NUL")?;
        let rc = unsafe { ds_save_document(self.ctx, self.doc, cpath.as_ptr()) };
        if rc != 0 {
            return bail("save");
        }
        Ok(())
    }

    /// (contents, subject) pairs, one per annotation on the page.
    pub fn annot_texts(&self, number: i32) -> Result<Vec<String>> {
        let mut list = DsStrList { items: std::ptr::null_mut(), n: 0, cap: 0 };
        let rc = unsafe { ds_annot_texts(self.ctx, self.doc, number, &mut list) };
        if rc != 0 {
            return bail("annot texts");
        }
        Ok(str_list_to_vec(&mut list))
    }

    /// Rewrite one annotation's contents and/or subject (None = leave as is).
    pub fn set_annot_texts(&self, number: i32, idx: i32, contents: Option<&str>, subject: Option<&str>) -> Result<()> {
        let c = contents.map(CString::new).transpose().context("NUL in annot text")?;
        let s = subject.map(CString::new).transpose().context("NUL in annot text")?;
        let rc = unsafe {
            ds_set_annot_texts(
                self.ctx,
                self.doc,
                number,
                idx,
                c.as_ref().map_or(std::ptr::null(), |x| x.as_ptr()),
                s.as_ref().map_or(std::ptr::null(), |x| x.as_ptr()),
            )
        };
        if rc != 0 {
            return bail("set annot texts");
        }
        Ok(())
    }

    /// (value, field label) pairs, one per form widget on the page.
    pub fn widget_texts(&self, number: i32) -> Result<Vec<String>> {
        let mut list = DsStrList { items: std::ptr::null_mut(), n: 0, cap: 0 };
        let rc = unsafe { ds_widget_texts(self.ctx, self.doc, number, &mut list) };
        if rc != 0 {
            return bail("widget texts");
        }
        Ok(str_list_to_vec(&mut list))
    }

    /// All outline/bookmark titles, depth-first.
    pub fn outline_titles(&self) -> Result<Vec<String>> {
        let mut list = DsStrList { items: std::ptr::null_mut(), n: 0, cap: 0 };
        let rc = unsafe { ds_outline_titles(self.ctx, self.doc, &mut list) };
        if rc != 0 {
            return bail("outline titles");
        }
        Ok(str_list_to_vec(&mut list))
    }
}

impl Drop for WriteDoc {
    fn drop(&mut self) {
        unsafe { ds_drop_document(self.ctx, self.doc) };
    }
}
