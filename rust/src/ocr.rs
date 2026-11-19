//! OCR for pages that have no text layer. Port of src/desensitize/ocr.py.
//!
//! Tesseract is invoked as a **local** process (no API calls, no uploads);
//! `OMP_THREAD_LIMIT=1` keeps each call single-threaded so rayon's parallel
//! page tasks map onto real cores.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Context, Result};

use crate::ffi::{self, FzMatrix, FzRect, Word};

pub const DEFAULT_DPI: i32 = 300;
pub const DEFAULT_LANG: &str = "eng";
pub const DEFAULT_MIN_CONF: f32 = 80.0;

pub const ROTATIONS: [i32; 4] = [0, 90, 180, 270];
pub const STRONG_CONF: f32 = 70.0;
pub const ENOUGH_STRONG_WORDS: usize = 6;
pub const LEGIBLE_ENOUGH: usize = 40;
pub const INK_FLOOR: f64 = 0.0003;

/// tesseract not on PATH, or its language pack is missing (exit code 4).
#[derive(Debug)]
pub struct OcrUnavailable(pub String);

/// Find the local tesseract binary (ocr._exe).
pub fn tesseract_exe() -> std::result::Result<PathBuf, OcrUnavailable> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path) {
        let cand = dir.join("tesseract");
        if cand.is_file() {
            return Ok(cand);
        }
    }
    Err(OcrUnavailable(
        "tesseract not found on PATH -- install it (Arch: pacman -S tesseract \
         tesseract-data-eng, Debian: apt install tesseract-ocr)"
            .to_string(),
    ))
}

/// Languages the installed tesseract carries (ocr.available_languages).
pub fn available_languages(exe: &Path) -> std::result::Result<HashSet<String>, OcrUnavailable> {
    let out = Command::new(exe)
        .arg("--list-langs")
        .output()
        .map_err(|e| OcrUnavailable(format!("tesseract --list-langs failed: {e}")))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let langs: HashSet<String> = text
        .lines()
        .skip(1)
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    if langs.is_empty() {
        return Err(OcrUnavailable(
            "tesseract language pack missing (install tesseract-data-eng)".to_string(),
        ));
    }
    Ok(langs)
}

/// One unique scratch file per render (ocr.py's TemporaryDirectory equivalent).
fn scratch_png(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir();
    dir.join(format!(
        "desens-rs-ocr-{}-{tag}-{n}.png",
        std::process::id()
    ))
}

/// Word confidence; native text words are trusted (ocr.word_conf).
pub fn word_conf(w: &Word) -> f32 {
    w.conf
}

pub fn strong_words(words: &[Word]) -> Vec<&Word> {
    words.iter().filter(|w| word_conf(w) >= STRONG_CONF).collect()
}

/// How many characters of this read like words, not noise (ocr.legible_score).
pub fn legible_score(words: &[Word]) -> usize {
    use std::sync::OnceLock;
    use regex::Regex;
    static LEGIBLE: OnceLock<Regex> = OnceLock::new();
    // "letters, a bracketed placeholder, a number, or money"
    let re = LEGIBLE.get_or_init(|| {
        Regex::new(r"^(?:[A-Za-z][A-Za-z'’\-]{1,}[.,:;!?)]?|\[[A-Z]+\]|\d{2,}|\$[\d,.]+)$")
            .unwrap()
    });
    let mut score = 0usize;
    for w in words {
        if word_conf(w) >= STRONG_CONF && re.is_match(&w.text) {
            score += w.text.chars().count();
        }
    }
    score
}

/// Ask tesseract which way up the page is (ocr.detect_orientation).
pub fn detect_orientation(exe: &Path, png: &Path) -> Option<i32> {
    let out = Command::new(exe).arg(png).arg("stdout").arg("--psm").arg("0").output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let re = regex::Regex::new(r"Rotate:\s*(\d+)").ok()?;
    let m = re.captures(&text)?;
    let deg: i32 = m.get(1)?.as_str().parse().ok()?;
    Some(deg % 360)
}

/// Run tesseract on a PNG and parse the TSV into words. Boxes come back in
/// RENDER PIXELS; the caller maps them through the inverse render ctm to get
/// display-space points (the ctm carries the dpi scale, so do NOT pre-divide
/// by it here -- that was a real bug that shrank every redaction box).
pub fn tesseract_words(
    exe: &Path,
    png: &Path,
    dpi: i32,
) -> std::result::Result<Vec<Word>, String> {
    let out = Command::new(exe)
        .env("OMP_THREAD_LIMIT", "1")
        .arg(png)
        .arg("stdout")
        .arg("--dpi")
        .arg(dpi.to_string())
        .arg("tsv")
        .output()
        .map_err(|e| format!("tesseract failed to start: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(stderr.trim().chars().take(200).collect());
    }
    let stdout = String::from_utf8_lossy(&out.stdout);

    let mut words = Vec::new();
    for line in stdout.lines().skip(1) {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 12 || cols[0] != "5" {
            continue;
        }
        let text = cols[11..].join("\t");
        let text = text.trim();
        if text.is_empty() {
            continue;
        }
        let (Ok(left), Ok(top), Ok(width), Ok(height), Ok(conf)) = (
            cols[6].parse::<f32>(),
            cols[7].parse::<f32>(),
            cols[8].parse::<f32>(),
            cols[9].parse::<f32>(),
            cols[10].parse::<f32>(),
        ) else {
            continue;
        };
        // pack block+paragraph into the block slot (ocr.py): tesseract's
        // line_num restarts per paragraph, so (block, line) must be unique
        let block_key: i32 = cols[2].parse::<i32>().unwrap_or(0) * 1000
            + cols[3].parse::<i32>().unwrap_or(0);
        let line_no: i32 = cols[4].parse().unwrap_or(0);
        let word_no: i32 = cols[5].parse().unwrap_or(0);
        words.push(Word {
            x0: left,
            y0: top,
            x1: left + width,
            y1: top + height,
            text: text.to_string(),
            block: block_key,
            line: line_no,
            no: word_no,
            conf,
        });
    }
    words.sort_by(|a, b| {
        let ra = (a.y0 * 10.0).round() / 10.0;
        let rb = (b.y0 * 10.0).round() / 10.0;
        ra.partial_cmp(&rb).unwrap().then(a.x0.partial_cmp(&b.x0).unwrap())
    });
    Ok(words)
}

fn invert_rect(r: FzRect, ctm: &FzMatrix) -> FzRect {
    // fz_transform_rect equivalent through the shim is not exposed for rect
    // math on the Rust side; do the 2x3 affine transform by hand.
    // ctm inverse: applied to display points gives render points, so here
    // we map render->display = inverse of (display->render).
    // a matrix [a b; c d; e f] inverse:
    let det = ctm.a * ctm.d - ctm.b * ctm.c;
    if det == 0.0 {
        return r;
    }
    let ia = ctm.d / det;
    let ib = -ctm.b / det;
    let ic = -ctm.c / det;
    let id = ctm.a / det;
    let ie = (ctm.c * ctm.f - ctm.d * ctm.e) / det;
    let if_ = (ctm.b * ctm.e - ctm.a * ctm.f) / det;
    let map = |x: f32, y: f32| (ia * x + ic * y + ie, ib * x + id * y + if_);
    // transform the four corners and take the bbox (rotation-safe)
    let (x1, y1) = map(r.x0, r.y0);
    let (x2, y2) = map(r.x1, r.y0);
    let (x3, y3) = map(r.x1, r.y1);
    let (x4, y4) = map(r.x0, r.y1);
    let xs = [x1, x2, x3, x4];
    let ys = [y1, y2, y3, y4];
    FzRect {
        x0: xs.iter().cloned().fold(f32::INFINITY, f32::min),
        y0: ys.iter().cloned().fold(f32::INFINITY, f32::min),
        x1: xs.iter().cloned().fold(f32::NEG_INFINITY, f32::max),
        y1: ys.iter().cloned().fold(f32::NEG_INFINITY, f32::max),
    }
}

/// OCR a page, un-rotating it when the ink is not upright (ocr.ocr_page_best).
/// Words come back in unrotated DISPLAY space, ready for cells and redaction
/// rects. `has_text_layer_hint` mirrors python's page-words short-circuit and
/// is used by callers, not here.
pub fn ocr_page_best(
    path: &str,
    page: i32,
    dpi: i32,
    lang: &str,
    exe: &Path,
) -> std::result::Result<Vec<Word>, OcrUnavailable> {
    // orientation guess at 150 dpi, like python
    let guess_png = scratch_png("orient");
    let _ctm = ffi::render_page_png(path, page, 150.0, 0, None, true, guess_png.to_str().unwrap_or(""))
        .map_err(|e| OcrUnavailable(format!("render for orientation: {e}")))?;
    let guess = detect_orientation(exe, &guess_png).unwrap_or(0);
    let _ = std::fs::remove_file(&guess_png);

    let mut order: Vec<i32> = vec![guess];
    for d in ROTATIONS {
        if d != guess {
            order.push(d);
        }
    }

    let mut best: Option<(i32, FzMatrix, Vec<Word>)> = None;
    let mut best_score = -1isize;
    for delta in order {
        let png = scratch_png("try");
        let ctm = ffi::render_page_png(path, page, dpi as f64, delta, None, false, png.to_str().unwrap_or(""))
            .map_err(|e| OcrUnavailable(format!("render page {page}: {e}")))?;
        let words = match tesseract_words(exe, &png, dpi) {
            Ok(w) => w,
            Err(e) => {
                let _ = std::fs::remove_file(&png);
                continue;
            }
        };
        let _ = std::fs::remove_file(&png);
        let score = legible_score(&words) as isize;
        if score > best_score {
            best_score = score;
            best = Some((delta, ctm, words.clone()));
        }
        if delta == guess && score >= LEGIBLE_ENOUGH as isize {
            break; // the guess reads: trust it
        }
    }

    let Some((delta, ctm, mut words)) = best else {
        return Ok(Vec::new());
    };
    let _ = delta;
    // map render-space boxes back into unrotated display space
    for w in words.iter_mut() {
        let r = invert_rect(FzRect { x0: w.x0, y0: w.y0, x1: w.x1, y1: w.y1 }, &ctm);
        w.x0 = r.x0;
        w.y0 = r.y0;
        w.x1 = r.x1;
        w.y1 = r.y1;
    }
    Ok(words)
}

/// OCR just a rect of a page (an embedded image) and return page-space words
/// (ocr.ocr_region_words). `block_namespace` keeps region blocks from
/// colliding with page words downstream.
pub fn ocr_region_words(
    path: &str,
    page: i32,
    rect: FzRect,
    dpi: i32,
    lang: &str,
    block_namespace: i32,
    exe: &Path,
) -> Result<Vec<Word>> {
    let png = scratch_png("region");
    let ctm = ffi::render_page_png(path, page, dpi as f64, 0, Some(rect), false, png.to_str().unwrap_or(""))?;
    let words = tesseract_words(exe, &png, dpi)
        .map_err(|e| anyhow!("tesseract region: {e}"))?;
    let _ = std::fs::remove_file(&png);
    let mut out = Vec::with_capacity(words.len());
    for mut w in words {
        let r = invert_rect(FzRect { x0: w.x0, y0: w.y0, x1: w.x1, y1: w.y1 }, &ctm);
        w.x0 = r.x0;
        w.y0 = r.y0;
        w.x1 = r.x1;
        w.y1 = r.y1;
        if block_namespace > 0 {
            w.block += block_namespace * 1_000_000;
        }
        out.push(w);
    }
    let _ = lang;
    Ok(out)
}

/// Embedded images worth OCR-ing (layout.image_regions): big enough to hold
/// text that matters; logos, icons and spacer tiles are not.
pub fn image_regions(
    images: &[ffi::ImageInfo],
    page_area: f32,
    min_pt: (f32, f32),
    min_src_px: i64,
    min_area_frac: f32,
) -> Vec<FzRect> {
    let mut regions: Vec<FzRect> = Vec::new();
    let mut seen: HashSet<(u32, u32, u32, u32, i32, i32)> = HashSet::new();
    for im in images {
        let w = im.x1 - im.x0;
        let h = im.y1 - im.y0;
        if w < min_pt.0 || h < min_pt.1 {
            continue;
        }
        if (im.src_w as i64) * (im.src_h as i64) < min_src_px {
            continue;
        }
        if w * h < page_area * min_area_frac {
            continue;
        }
        let key = (
            (im.x0 * 10.0) as u32,
            (im.y0 * 10.0) as u32,
            (w * 10.0) as u32,
            (h * 10.0) as u32,
            im.src_w,
            im.src_h,
        );
        if !seen.insert(key) {
            continue;
        }
        regions.push(FzRect { x0: im.x0, y0: im.y0, x1: im.x1, y1: im.y1 });
    }
    regions
}

/// Pre-flight check shared by the CLI (exit code 4).
pub fn require_tesseract(lang: &str) -> std::result::Result<PathBuf, OcrUnavailable> {
    let exe = tesseract_exe()?;
    let langs = available_languages(&exe)?;
    if !lang.is_empty() && !langs.contains(lang) {
        let mut sorted: Vec<&String> = langs.iter().collect();
        sorted.sort();
        return Err(OcrUnavailable(format!(
            "tesseract language '{lang}' not installed (have: {})",
            sorted.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        )));
    }
    Ok(exe)
}

