//! The redaction engine: plan marks per page, apply them, then re-read the
//! result. Port of src/desensitize/engine.py (text-layer path).
//!
//! Destructive redaction: `pdf_redact_page` deletes the glyphs under each
//! redaction rectangle (PDF_REDACT_TEXT_REMOVE), the same MuPDF operation the
//! Python tool performs through pymupdf. Metadata is stripped. The verify
//! pass then re-opens the copy and proves nothing it removed survived.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::detect::{detect_in_cell, label_only, KnownNames, NameFreq, Span};
use crate::ffi::{self, FzRect, Word};
use crate::layout::{words_for_span, Cell};
use crate::patterns::{norm, patterns, sensitive_tokens};

pub const HEADER_MARGIN_X: f32 = 85.0; // a label this far left is a section header
pub const SAME_LINE_TOL: f32 = 0.35; // * label height
pub const VALUE_BELOW_GAP: f32 = 70.0;
pub const BLOCK_GAP: f32 = 95.0; // hard stop for a section header's value block
pub const BLOCK_LINE_GAP: f32 = 24.0; // once a block starts, its lines stack densely
pub const MAX_SAME_LINE_VALUES: usize = 60; // a wide table row is still one row
pub const MAX_BLOCK_VALUES: usize = 500; // a 60-row table under one header is one block
pub const DEFAULT_GAP: f32 = 16.0;

pub type Counts = BTreeMap<String, usize>;
pub type Hashes = HashMap<String, String>; // digest -> category
pub type Vocab = HashSet<String>;

#[derive(Clone, Debug)]
pub struct Mark {
    pub page: i32,
    pub words: Vec<Word>,
    pub label: &'static str,
}

#[derive(Clone, Debug)]
pub struct PagePlan {
    pub cells: Vec<Cell>,
    pub ocr_mode: bool,
    /// whole-page plain text (source vocabulary for verification)
    pub text: String,
    /// embedded-image blocks (milestone-1 caveat: pixels not proven)
    pub image_blocks: i32,
}

pub struct DocumentResult {
    pub file_name: String,
    pub pages: usize,
    pub output: Option<PathBuf>,
    pub counts: Counts,
    pub mode: &'static str,
    pub ocr_pages: usize,
    pub image_regions: usize,
    pub unreadable_pages: Vec<i32>,
    /// total embedded images across pages (caveat input for the report)
    pub image_blocks: usize,
}

impl DocumentResult {
    pub fn as_dict(&self) -> serde_json::Value {
        let counts: serde_json::Map<String, serde_json::Value> = self
            .counts
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::from(*v)))
            .collect();
        serde_json::json!({
            "file": self.file_name,
            "pages": self.pages,
            "output": self.output.as_ref().map(|p| p.display().to_string()),
            "mode": self.mode,
            "ocr_pages": self.ocr_pages,
            "image_regions_ocrd": self.image_regions,
            "unreadable_pages": self.unreadable_pages,
            "redactions_by_type": counts,
        })
    }
}

/// Strip identifiers out of the filename too (engine.safe_output_name).
pub fn safe_output_name(path: &Path) -> String {
    let stem_raw = path.file_stem().and_then(|s| s.to_str()).unwrap_or("document");
    let stem = patterns()
        .email_re
        .replace_all(stem_raw, "redacted")
        .into_owned();
    let digit_re = regex::Regex::new(r"\d{4,}").unwrap();
    let stem = digit_re.replace_all(&stem, "redacted").into_owned();
    let scrub_re = regex::Regex::new(r"[^\w \-.()]+").unwrap();
    let stem = scrub_re.replace_all(&stem, "_").into_owned();
    let stem = stem.trim_matches(|c: char| c == ' ' || c == '.' || c == '_' || c == '-').to_string();
    let stem = if stem.is_empty() { "document".to_string() } else { stem };
    format!("{stem}.pdf")
}

fn take(
    marks: &mut Vec<Mark>,
    hashes: &mut Hashes,
    counts: &mut Counts,
    page_no: i32,
    words: &[Word],
    label: &'static str,
) {
    *counts.entry(label.to_string()).or_insert(0) += 1;
    marks.push(Mark { page: page_no, words: words.to_vec(), label });
    let joined = words
        .iter()
        .map(|w| w.text.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    for tok in sensitive_tokens(&joined) {
        hashes.entry(crate::patterns::h(&tok)).or_insert_with(|| label.to_string());
    }
}

/// Port of engine._plan_page. Returns marks (mutates shared state like the
/// Python original); ocr_mode adds the fail-closed low-confidence sweep.
#[allow(clippy::too_many_arguments)]
pub fn plan_page(
    page_no: i32,
    cells: &[Cell],
    known_names: &KnownNames,
    name_freq: &NameFreq,
    ocr_mode: bool,
    min_conf: f32,
    marks: &mut Vec<Mark>,
    hashes: &mut Hashes,
    counts: &mut Counts,
    vocab: &mut Vocab,
    debug_marks: bool,
) {
    let p = patterns();

    // --- uncertain OCR words fail closed -----------------------------
    if ocr_mode {
        let digitish = regex::Regex::new(r"\d").unwrap();
        for cell in cells {
            for w in &cell.words {
                if w.conf < min_conf && (digitish.is_match(&w.text) || w.text.chars().count() >= 3) {
                    take(marks, hashes, counts, page_no, std::slice::from_ref(w), "UNCLEAR");
                }
            }
        }
    }

    // --- label-driven cells ------------------------------------------
    let mut ordered: Vec<usize> = (0..cells.len()).collect();
    ordered.sort_by(|&a, &b| {
        let wa = &cells[a].words[0];
        let wb = &cells[b].words[0];
        wa.y0.partial_cmp(&wb.y0).unwrap().then(wa.x0.partial_cmp(&wb.x0).unwrap())
    });

    for idx in 0..cells.len() {
        let cell = &cells[idx];
        let Some(lab) = label_only(&cell.text) else { continue };
        let lw = &cell.words[0];
        let lab_y0 = lw.y0;
        let lab_y1 = lw.y1;
        let lab_x = lw.x0;
        let tol = 1.5f32.max((lab_y1 - lab_y0) * SAME_LINE_TOL);
        let header_style = lab_x <= HEADER_MARGIN_X && !p.salutation_re.is_match(&cell.text);

        // values to the right on the same line ("Account Number  XXXX")
        let mut taken = 0usize;
        for &j in &ordered {
            if j == idx || cells[j].text.trim().is_empty() {
                continue;
            }
            let c = &cells[j];
            let w = &c.words[0];
            if (w.y0 - lab_y0).abs() > tol || w.x0 <= lab_x {
                continue;
            }
            if label_only(&c.text).is_some() {
                continue;
            }
            if p.header_cell_re.is_match(c.text.trim()) {
                continue; // sibling header, not this label's value
            }
            take(marks, hashes, counts, page_no, &c.words, lab);
            taken += 1;
            if taken >= MAX_SAME_LINE_VALUES {
                break;
            }
        }
        if taken > 0 {
            continue;
        }

        if !header_style {
            // one value line directly under the label
            for &j in &ordered {
                if j == idx || cells[j].text.trim().is_empty() {
                    continue;
                }
                let c = &cells[j];
                let w = &c.words[0];
                if !(-1.0..=VALUE_BELOW_GAP).contains(&(w.y0 - lab_y1)) {
                    continue;
                }
                if !(-6.0..=45.0).contains(&(w.x0 - lab_x)) {
                    continue;
                }
                if label_only(&c.text).is_some() {
                    break;
                }
                take(marks, hashes, counts, page_no, &c.words, lab);
            }
            continue;
        }

        // section header ("Names", "Employers"): take the whole value block
        let start_y = lab_y1;
        let mut last_y1 = lab_y1;
        let mut first_line = true;
        let mut n = 0usize;
        for &j in &ordered {
            if j == idx || cells[j].text.trim().is_empty() {
                continue;
            }
            let c = &cells[j];
            let w = &c.words[0];
            if w.y0 <= start_y + 1.0 {
                continue; // siblings share a line with the block
            }
            let other = label_only(&c.text);
            if let Some(other) = other {
                // a label of a different family ends the block; same-family
                // sub-labels ("AKA" under "Names") do not
                if other != lab {
                    break;
                }
                continue;
            }
            let gap = w.y0 - last_y1;
            if gap > BLOCK_GAP {
                break;
            }
            if !first_line && gap > BLOCK_LINE_GAP {
                break;
            }
            take(marks, hashes, counts, page_no, &c.words, lab);
            last_y1 = last_y1.max(c.words.last().map(|w| w.y1).unwrap_or(0.0));
            first_line = false;
            n += 1;
            if n >= MAX_BLOCK_VALUES {
                break;
            }
        }
    }

    // --- span-driven cells -------------------------------------------
    // a cue on the previous line of the same block still applies to this one
    let mut prefixes: HashMap<usize, String> = HashMap::new();
    let mut by_block: BTreeMap<i32, Vec<usize>> = BTreeMap::new();
    for (idx, cell) in cells.iter().enumerate() {
        by_block.entry(cell.words[0].block).or_default().push(idx);
    }
    for items in by_block.values() {
        let mut items = items.clone();
        items.sort_by(|&a, &b| {
            let wa = &cells[a].words[0];
            let wb = &cells[b].words[0];
            wa.y0.partial_cmp(&wb.y0).unwrap().then(wa.x0.partial_cmp(&wb.x0).unwrap())
        });
        let mut prev = String::new();
        for &idx in &items {
            let cut = crate::patterns::char_offset_back(&prev, prev.len(), 90);
            prefixes.insert(idx, prev[cut..].to_string());
            prev = cells[idx].text.clone();
        }
    }

    for idx in 0..cells.len() {
        let cell = &cells[idx];
        let prefix = prefixes.get(&idx).cloned().unwrap_or_default();
        let full = if prefix.is_empty() {
            cell.text.clone()
        } else {
            format!("{prefix} {}", cell.text)
        };
        let off = full.len() - cell.text.len();
        let spans: Vec<Span> = detect_in_cell(&full, known_names, name_freq, ocr_mode)
            .into_iter()
            .filter(|s| s.end as isize - off as isize > 0)
            .map(|s| Span {
                start: s.start.saturating_sub(off),
                end: s.end.saturating_sub(off).min(cell.text.len()),
                label: s.label,
            })
            .collect();

        if spans.is_empty() {
            for m in p.vocab_re.find_iter(&cell.text) {
                vocab.insert(norm(p.vocab_re.as_str(&m, &cell.text)));
            }
        } else {
            let mut pos = 0usize;
            for s in &spans {
                for m in p.vocab_re.find_iter(&cell.text[pos..s.start]) {
                    vocab.insert(norm(p.vocab_re.as_str(&m, &cell.text)));
                }
                pos = pos.max(s.end);
            }
            for m in p.vocab_re.find_iter(&cell.text[pos..]) {
                vocab.insert(norm(p.vocab_re.as_str(&m, &cell.text)));
            }
        }

        for s in &spans {
            let words = words_for_span(&cell.words, cell.text.len(), s.start, s.end);
            if words.is_empty() {
                continue;
            }
            take(marks, hashes, counts, page_no, &words, s.label);
            for tok in sensitive_tokens(&cell.text[s.start..s.end]) {
                hashes
                    .entry(crate::patterns::h(&tok))
                    .or_insert_with(|| s.label.to_string());
            }
        }
    }

    if debug_marks {
        for m in marks.iter().filter(|m| m.page == page_no) {
            if let Some(w) = m.words.first() {
                let width = m.words.iter().map(|w| w.x1).fold(f32::NEG_INFINITY, f32::max)
                    - m.words.iter().map(|w| w.x0).fold(f32::INFINITY, f32::min);
                let height = m.words.iter().map(|w| w.y1).fold(f32::NEG_INFINITY, f32::max)
                    - m.words.iter().map(|w| w.y0).fold(f32::INFINITY, f32::min);
                println!(
                    "   mark p{:>2} {:<9} y={:6.1} x={:6.1} words={} w={:.0} h={:.0}",
                    m.page + 1,
                    m.label,
                    w.y0,
                    w.x0,
                    m.words.len(),
                    width,
                    height
                );
            }
        }
    }
}

/// Replace every detected span in a plain string (engine._redact_string).
/// `whole` is for short navigational strings: half a bookmark title still
/// names the person, so replacement is all-or-nothing there.
pub fn redact_string(
    text: &str,
    known_names: &KnownNames,
    name_freq: &NameFreq,
    hashes: &mut Hashes,
    counts: &mut Counts,
    whole: bool,
) -> (String, usize) {
    if text.is_empty() {
        return (text.to_string(), 0);
    }
    let spans = detect_in_cell(text, known_names, name_freq, false);
    if spans.is_empty() {
        return (text.to_string(), 0);
    }
    for s in &spans {
        *counts.entry(s.label.to_string()).or_insert(0) += 1;
        for tok in sensitive_tokens(&text[s.start..s.end]) {
            hashes
                .entry(crate::patterns::h(&tok))
                .or_insert_with(|| s.label.to_string());
        }
    }
    if whole {
        return ("[REDACTED]".to_string(), spans.len());
    }
    let mut out = String::new();
    let mut pos = 0usize;
    for s in &spans {
        out.push_str(&text[pos..s.start]);
        out.push_str(&format!("[{}]", s.label));
        pos = pos.max(s.end);
    }
    out.push_str(&text[pos..]);
    (out, spans.len())
}

/// Scrub annotation payloads (contents + subject) on every page, before any
/// redact annot is created (annot indices stay stable that way).
/// Returns the number of annots rewritten.
pub fn scrub_annots(
    doc: &ffi::WriteDoc,
    pages: i32,
    known_names: &KnownNames,
    name_freq: &NameFreq,
    hashes: &mut Hashes,
    counts: &mut Counts,
) -> anyhow::Result<usize> {
    let mut rewritten = 0usize;
    for page in 0..pages {
        let texts = doc.annot_texts(page)?;
        let mut new_pairs: Vec<(usize, Option<String>, Option<String>)> = Vec::new();
        for i in 0..texts.len() / 2 {
            let contents = &texts[i * 2];
            let subject = &texts[i * 2 + 1];
            let mut new_contents: Option<String> = None;
            let mut new_subject: Option<String> = None;
            if !contents.trim().is_empty() {
                let (s, hits) = redact_string(contents, known_names, name_freq, hashes, counts, false);
                if hits > 0 {
                    new_contents = Some(s);
                }
            }
            if !subject.trim().is_empty() {
                // subject lines are navigational: all-or-nothing
                let (s, hits) = redact_string(subject, known_names, name_freq, hashes, counts, true);
                if hits > 0 {
                    new_subject = Some(s);
                }
            }
            if new_contents.is_some() || new_subject.is_some() {
                new_pairs.push((i, new_contents, new_subject));
            }
        }
        for (idx, contents, subject) in new_pairs {
            doc.set_annot_texts(page, idx as i32, contents.as_deref(), subject.as_deref())?;
            rewritten += 1;
        }
    }
    Ok(rewritten)
}

/// Burn the planned marks into the document and write the copy.
pub fn apply_and_save(
    doc: &ffi::WriteDoc,
    pages: i32,
    marks_by_page: &BTreeMap<i32, Vec<(Vec<Word>, &'static str)>>,
    out_path: &Path,
) -> anyhow::Result<usize> {
    let mut applied = 0usize;
    for page in 0..pages {
        let Some(page_marks) = marks_by_page.get(&page) else { continue };
        let rects: Vec<FzRect> = page_marks
            .iter()
            .flat_map(|(words, _)| words.iter())
            .map(|w| FzRect { x0: w.x0, y0: w.y0, x1: w.x1, y1: w.y1 })
            .collect();
        if rects.is_empty() {
            continue;
        }
        doc.apply_redactions(page, &rects, false)?;
        applied += rects.len();
    }
    doc.scrub_metadata()?;
    doc.save(&out_path.display().to_string())?;
    Ok(applied)
}

/// Normalised word tokens, for comparing a copy against its source
/// (verify.tokens).
pub fn tokens(text: &str) -> Vocab {
    let p = patterns();
    p.word_re
        .find_iter(text)
        .iter()
        .map(|m| norm(p.word_re.as_str(m, text)))
        .filter(|t| !t.is_empty())
        .collect()
}
