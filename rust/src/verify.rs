//! Self-check: re-open the copies and look for anything sensitive that
//! survived. Port of src/desensitize/verify.py (text-layer pass + object
//! strings readable through MuPDF 1.28's public API).
//!
//! Two independent checks, both value-free:
//!
//! 1. Pattern scan -- re-run the value regexes over the copy.
//! 2. Known-value scan -- the engine recorded a digest of every value it
//!    redacted; any of those tokens still present is a leak. A token only
//!    counts if it is *not* part of the copy's general vocabulary.

use std::collections::{BTreeMap, HashSet};

use crate::engine::{tokens, Counts, Hashes, Vocab};
use crate::ffi;
use crate::layout::{cells_from_words, DEFAULT_GAP};
use crate::patterns::{is_date_like, norm, patterns};

#[derive(Default, Debug, Clone)]
pub struct VerificationReport {
    pub pattern_hits: Counts,
    pub leak_total: usize,
    pub leaks_by_category: BTreeMap<String, usize>,
    /// (category, token length, masked token) -- never a value
    pub masked_samples: Vec<(String, usize, String)>,
}

impl VerificationReport {
    pub fn clean(&self) -> bool {
        self.leak_total == 0 && self.pattern_hits.values().all(|&v| v == 0)
    }

    pub fn merge(&mut self, other: VerificationReport) {
        for (k, v) in other.pattern_hits {
            *self.pattern_hits.entry(k).or_insert(0) += v;
        }
        self.leak_total += other.leak_total;
        for (k, v) in other.leaks_by_category {
            *self.leaks_by_category.entry(k).or_insert(0) += v;
        }
        let room = 25usize.saturating_sub(self.masked_samples.len());
        self.masked_samples.extend(other.masked_samples.into_iter().take(room));
    }

    pub fn as_dict(&self) -> serde_json::Value {
        let hits: serde_json::Map<String, serde_json::Value> = self
            .pattern_hits
            .iter()
            .filter(|(_, &v)| v > 0)
            .map(|(k, v)| (k.clone(), serde_json::Value::from(*v)))
            .collect();
        let cats: serde_json::Map<String, serde_json::Value> = self
            .leaks_by_category
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::from(*v)))
            .collect();
        serde_json::json!({
            "residual_pattern_hits": hits,
            "residual_known_value_hits": self.leak_total,
            "by_category": cats,
        })
    }
}

fn mask(tok: &str) -> String {
    let chars: Vec<char> = tok.chars().collect();
    let n = chars.len();
    let mut out = String::new();
    if let Some(first) = chars.first() {
        out.push(*first);
    }
    for _ in 1..n.saturating_sub(1) {
        out.push('*');
    }
    if n >= 2 {
        out.push(chars[n - 1]);
    }
    out
}

/// Re-run the value regexes, minus hits that are plainly not identifiers
/// (verify._count_pattern_hits). A pattern that appears only in the copy and
/// not in the input is the reader's own noise, not a leak.
fn count_pattern_hits(text: &str, source_vocab: Option<&Vocab>) -> Counts {
    let p = patterns();
    let has_digit = text.chars().any(|c| c.is_ascii_digit());
    let mut hits: Counts = BTreeMap::new();
    for (label, rx, needs_digit) in &p.patterns {
        if *needs_digit && !has_digit {
            continue; // cannot match a digit-free cell
        }
        for m in rx.find_iter(text) {
            let hit = &text[m.start..m.end];
            if *label == "NUMBER" && is_date_like(hit) {
                continue;
            }
            if let Some(sv) = source_vocab {
                if !sv.contains(&norm(hit)) {
                    continue;
                }
            }
            *hits.entry(label.to_string()).or_insert(0) += 1;
        }
    }
    hits
}

/// Pattern hits and remembered-value hits for one run of text
/// (verify._scan_text).
#[allow(clippy::too_many_arguments)]
fn scan_text(
    report: &mut VerificationReport,
    text: &str,
    redacted_hashes: &Hashes,
    unredacted_vocab: &Vocab,
    sample_limit: usize,
    source_vocab: Option<&Vocab>,
) {
    let p = patterns();
    for (k, v) in count_pattern_hits(text, source_vocab) {
        *report.pattern_hits.entry(k).or_insert(0) += v;
    }
    let mut seen: HashSet<&str> = HashSet::new();
    for m in p.word_re.find_iter(text) {
        let tok = &text[m.start..m.end];
        if seen.contains(tok) {
            continue;
        }
        // our own placeholder is not a leak
        if tok.starts_with('[') && tok.ends_with(']') && is_placeholder(tok) {
            continue;
        }
        let mut cat = redacted_hashes
            .get(&crate::patterns::h(tok))
            .or_else(|| redacted_hashes.get(&crate::patterns::h(tok.trim_matches(|c: char| ".,:;()".contains(c)))))
            .cloned();
        if cat.is_some() && unredacted_vocab.contains(&norm(tok)) {
            cat = None; // generic word, not a value
        }
        let Some(cat) = cat else { continue };
        seen.insert(tok);
        report.leak_total += 1;
        *report.leaks_by_category.entry(cat.clone()).or_insert(0) += 1;
        if report.masked_samples.len() < sample_limit {
            report.masked_samples
                .push((cat.clone(), tok.chars().count(), mask(tok)));
        }
    }
}

fn is_placeholder(tok: &str) -> bool {
    // PLACEHOLDER_RE.fullmatch -- "\[[A-Z]+\]"
    let inner = &tok[1..tok.len() - 1];
    !inner.is_empty() && inner.chars().all(|c| c.is_ascii_uppercase())
}

/// Look for leaks in one redacted copy: page text (parallel), then the
/// object strings MuPDF exposes -- annotation contents/subjects, form-field
/// values, outline titles (verify.scan_copy).
pub fn scan_copy(
    path: &str,
    redacted_hashes: &Hashes,
    unredacted_vocab: &Vocab,
    sample_limit: usize,
    source_vocab: Option<&Vocab>,
) -> anyhow::Result<VerificationReport> {
    let pages = ffi::count_pages(path)?;
    use rayon::prelude::*;

    // pages in parallel: each worker opens its own read-only handle
    let per_page: Vec<anyhow::Result<VerificationReport>> = (0..pages)
        .into_par_iter()
        .map(|pno| {
            let ex = ffi::extract_page(path, pno)?;
            let cells = cells_from_words(ex.words, DEFAULT_GAP);
            let mut rep = VerificationReport::default();
            for cell in &cells {
                scan_text(&mut rep, &cell.text, redacted_hashes, unredacted_vocab, sample_limit, source_vocab);
            }
            Ok(rep)
        })
        .collect();
    let mut report = VerificationReport::default();
    for r in per_page {
        report.merge(r?);
    }

    // object strings: annots, form fields, bookmarks
    let doc = ffi::WriteDoc::open(path)?;
    for page in 0..pages {
        let annots = doc.annot_texts(page)?;
        for (i, s) in annots.iter().enumerate() {
            if s.trim().is_empty() {
                continue;
            }
            scan_text(&mut report, s, redacted_hashes, unredacted_vocab, sample_limit, source_vocab);
            let _ = i;
        }
        let widgets = doc.widget_texts(page)?;
        for chunk in widgets.chunks(2) {
            let value = &chunk[0]; // (value, field label) pairs
            if value.trim().is_empty() {
                continue;
            }
            scan_text(&mut report, value, redacted_hashes, unredacted_vocab, sample_limit, source_vocab);
        }
    }
    for title in doc.outline_titles()? {
        scan_text(&mut report, &title, redacted_hashes, unredacted_vocab, sample_limit, source_vocab);
    }
    drop(doc);

    Ok(report)
}

/// Deep check: OCR the copy's *pixels* and look for redacted values again
/// (verify.ocr_rescan). On a scan the text layer is ours (we wrote it), so
/// scanning it proves only that we are consistent. This re-reads the picture.
///
/// `pixel_pages`: ocr_mode pages -> None (whole page), region pages ->
/// Some(rects). Pages run in parallel (tesseract is one core per call).
#[allow(clippy::too_many_arguments)]
pub fn ocr_rescan(
    path: &str,
    pixel_pages: &BTreeMap<i32, Option<Vec<ffi::FzRect>>>,
    redacted_hashes: &Hashes,
    unredacted_vocab: &Vocab,
    sample_limit: usize,
    source_vocab: Option<&Vocab>,
    dpi: i32,
    lang: &str,
    exe: &std::path::Path,
) -> anyhow::Result<VerificationReport> {
    use rayon::prelude::*;
    let entries: Vec<(&i32, &Option<Vec<ffi::FzRect>>)> = pixel_pages.iter().collect();
    let per_page: Vec<anyhow::Result<VerificationReport>> = entries
        .into_par_iter()
        .map(|(&pno, clips)| {
            let mut rep = VerificationReport::default();
            let mut words: Vec<ffi::Word> = Vec::new();
            match clips {
                None => {
                    // read the whole page the way a reader would
                    let best = crate::ocr::ocr_page_best(path, pno, dpi, lang, exe)
                        .map_err(|e| anyhow::anyhow!("{}", e.0))?;
                    words.extend(best);
                }
                Some(rects) => {
                    for (i, rect) in rects.iter().enumerate() {
                        let w = crate::ocr::ocr_region_words(
                            path, pno, *rect, dpi, lang, (i + 1) as i32, exe,
                        )?;
                        words.extend(w);
                    }
                }
            }
            for cell in crate::layout::cells_from_words(words, crate::layout::DEFAULT_GAP) {
                let text = &cell.text;
                for (k, v) in count_pattern_hits(text, source_vocab) {
                    *rep.pattern_hits.entry(k).or_insert(0) += v;
                }
                let mut seen: HashSet<&str> = HashSet::new();
                for tok in text.split_whitespace() {
                    if seen.contains(tok) {
                        continue;
                    }
                    let is_ph = tok.starts_with('[')
                        && tok.ends_with(']')
                        && tok.len() > 2
                        && tok[1..tok.len() - 1].chars().all(|c| c.is_ascii_uppercase());
                    if is_ph {
                        continue;
                    }
                    seen.insert(tok);
                    let mut cat = redacted_hashes
                        .get(&crate::patterns::h(tok))
                        .or_else(|| {
                            redacted_hashes
                                .get(&crate::patterns::h(tok.trim_matches(|c: char| ".,:;()".contains(c))))
                        })
                        .cloned();
                    if cat.is_some() && unredacted_vocab.contains(&norm(tok)) {
                        cat = None;
                    }
                    let Some(cat) = cat else { continue };
                    rep.leak_total += 1;
                    if std::env::var_os("DS_DEBUG_LEAKS").is_some() {
                        eprintln!("[debug-leak] {cat} token={tok:?}");
                    }
                    *rep.leaks_by_category.entry(cat.clone()).or_insert(0) += 1;
                    if rep.masked_samples.len() < sample_limit {
                        rep.masked_samples
                            .push((cat, tok.chars().count(), mask(tok)));
                    }
                }
            }
            Ok(rep)
        })
        .collect();
    let mut report = VerificationReport::default();
    for r in per_page {
        report.merge(r?);
    }
    Ok(report)
}
