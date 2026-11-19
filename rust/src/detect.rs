//! Decide what to redact inside a cell of text.
//!
//! Direct port of src/desensitize/detect.py. `detect_in_cell` is the single
//! entry point: given a cell's text plus the learned name vocabulary it
//! returns non-overlapping (start, end, label) spans, combining, in priority
//! order:
//!
//! 1. "Label: value" prefixes  -- value runs to the end of the cell
//! 2. Value regexes            -- SSN, email, phone, address, ZIP, long IDs
//! 3. DOB context             -- dates/years on a line that mentions birth
//! 4. Learned names           -- bare mentions of a name seen in a labelled field
//! 5. Whole-cell address lines
//! 6. Person-name candidates  -- capitalised runs, minus company vocabulary

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::Path;

use crate::layout::Cell;
use crate::patterns::{
    char_offset, char_offset_back, digit_count, floor_boundary, fmatch, patterns, py_isupper,
};

pub type NameFreq = HashMap<String, usize>;
pub type KnownNames = HashSet<String>;

#[derive(Clone, Debug)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub label: &'static str,
}

fn strip_dots(s: &str) -> &str {
    s.trim_matches('.')
}

    /// Return the label family if the cell is nothing but a field label.
    /// No table entry can match a cell longer than 60 chars -- the longest
    /// pattern is under 47 -- so longer cells skip the ~150-regex sweep.
    pub fn label_only(text: &str) -> Option<&'static str> {
        let p = patterns();
        if text.chars().count() > 60 {
            return None;
        }
        let variants = [
            text.to_string(),
            text.replace("(s)", "s").replace("(es)", "s"),
        ];
    for (lab, res) in &p.label_res {
        for rx in res {
            for v in &variants {
                if rx.is_match(v) {
                    return Some(lab);
                }
            }
        }
    }
    None
}

/// Sort and coalesce overlapping spans, keeping the earliest label.
pub fn merge_spans(spans: Vec<Span>) -> Vec<Span> {
    if spans.is_empty() {
        return Vec::new();
    }
    let mut sorted: Vec<Span> = spans;
    sorted.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    let mut merged: Vec<Span> = Vec::new();
    for s in sorted {
        match merged.last_mut() {
            Some(m) if s.start < m.end => {
                if s.end > m.end {
                    m.end = s.end;
                }
            }
            _ => merged.push(s),
        }
    }
    merged
}

/// Conservative person-name detection (detect.name_spans).
pub fn name_spans(text: &str, known_names: &KnownNames, name_freq: &NameFreq) -> Vec<Span> {
    let p = patterns();
    let toks: Vec<(&str, usize, usize)> = p
        .token_re
        .find_iter(text)
        .iter()
        .map(|m| (&text[m.start..m.end], m.start, m.end))
        .collect();
    let mut spans = Vec::new();
    let n = toks.len();
    let mut i = 0usize;
    while i < n {
        let mut j = i;
        while j + 1 < n && p.gap_ok_re.is_match(&text[toks[j].2..toks[j + 1].1]) {
            j += 1;
        }
        // leading capitalised stretch only
        let mut cap: Vec<usize> = Vec::new(); // indices into toks
        for k in i..=j {
            let t = toks[k].0;
            if t.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) || py_isupper(t) {
                cap.push(k);
            } else {
                break;
            }
        }

        let mut accepted: Vec<(usize, usize)> = Vec::new();
        // longest window first, then shorter ones inside it
        let max_size = cap.len().min(4);
        for size in (2..=max_size).rev() {
            if cap.len() < size {
                continue;
            }
            for s in 0..=(cap.len() - size) {
                let win: Vec<usize> = (s..s + size).collect();
                let lower: Vec<String> = win
                    .iter()
                    .map(|&k| toks[k].0.to_lowercase())
                    .map(|w| strip_dots(&w).to_string())
                    .collect();
                let lower_ref: Vec<&str> = lower.iter().map(|w| w.as_str()).collect();
                if lower_ref.iter().any(|w| p.org_markers.contains(w)) {
                    continue;
                }
                if lower_ref.iter().all(|w| p.name_stop.contains(w)) {
                    continue;
                }
                if !lower_ref
                    .iter()
                    .any(|w| !p.name_stop.contains(w) && w.len() >= 2)
                {
                    continue;
                }
                // all-caps runs are headings/transactions until taught otherwise
                if win.iter().all(|&k| py_isupper(toks[k].0)) {
                    if lower_ref
                        .iter()
                        .any(|w| p.allcaps_stop.contains(w) || p.org_markers.contains(w))
                    {
                        continue;
                    }
                    if !lower_ref.iter().any(|w| known_names.contains(*w)) {
                        continue;
                    }
                }
                let key2 = lower_ref[..2.min(lower_ref.len())].join(" ");
                let key3 = lower_ref[..3.min(lower_ref.len())].join(" ");
                let known_hit = lower_ref.iter().any(|w| known_names.contains(*w));
                if !(known_hit
                    || name_freq.get(&key2).copied().unwrap_or(0) >= 2
                    || name_freq.get(&key3).copied().unwrap_or(0) >= 2)
                {
                    continue;
                }
                let start = toks[win[0]].1;
                let end = toks[*win.last().unwrap()].2;
                if accepted.iter().any(|&(a, b)| start < b && end > a) {
                    continue;
                }
                accepted.push((start, end));
                spans.push(Span { start, end, label: "NAME" });
            }
        }
        i = j + 1;
    }
    spans
}

/// Names that follow a salutation or signature cue (detect.person_context_spans).
pub fn person_context_spans(text: &str) -> Vec<Span> {
    use std::sync::OnceLock;
    use regex::Regex as R;
    static PERSON_RUN: OnceLock<R> = OnceLock::new();
    let run = PERSON_RUN.get_or_init(|| {
        // _PERSON_RUN_RE without its lookbehind -- checked manually below
        R::new(r"^([A-Z][A-Za-z'’\-]+(?:\s+(?:[A-Z]\.|[A-Z][A-Za-z'’\-]+)){1,3})").unwrap()
    });
    let p = patterns();
    let mut spans = Vec::new();
    for r in p.person_ctx_re.find_iter(text) {
        let m = match r {
            Ok(m) => m,
            Err(_) => continue,
        };
        let pos = m.end();
        // Python: _PERSON_RUN_RE.match(text, pos) -- the lookbehind means the
        // char before pos must not be a letter (and pos may be 0)
        if pos > 0 {
            let prev = &text[..pos];
            if let Some(c) = prev.chars().last() {
                if c.is_ascii_alphabetic() {
                    continue;
                }
            }
        }
        let Some(caps) = run.captures(&text[pos..]) else {
            continue;
        };
        let Some(g1) = caps.get(1) else { continue };
        let mut keep: Vec<&str> = Vec::new();
        for tok in g1.as_str().split_whitespace() {
            let low_s = tok.to_lowercase();
            let low = strip_dots(&low_s);
            if p.org_markers.contains(low) || p.name_stop.contains(low) {
                break;
            }
            keep.push(tok);
        }
        if keep.len() < 2 {
            continue; // one capitalised word is too weak
        }
        let joined = keep.join(" ");
        let end = pos + joined.len();
        spans.push(Span { start: pos, end, label: "NAME" });
    }
    spans
}

fn has_state_abbr(text: &str) -> bool {
    patterns().state_abbr_re.is_match(text)
}

fn has_street_word(text: &str) -> bool {
    let p = patterns();
    let toks: Vec<&str> = p.token_re.find_iter(text).iter().map(|m| &text[m.start..m.end]).collect();
    if toks.iter().any(|t| p.form_words.contains(t.to_lowercase().as_str())) {
        return false;
    }
    toks.iter().any(|t| {
        t.chars().next().map(|c| c.is_uppercase()).unwrap_or(false)
            && t.chars().count() >= 4
            && !p.name_stop.contains(t.to_lowercase().as_str())
    })
}

/// Return non-overlapping spans to redact in this cell (detect.detect_in_cell).
pub fn detect_in_cell(
    text: &str,
    known_names: &KnownNames,
    name_freq: &NameFreq,
    ocr_mode: bool,
) -> Vec<Span> {
    let p = patterns();
    let mut spans: Vec<Span> = Vec::new();

    // sound prefilters: label-prefix patterns all require ':'; every value
    // pattern except the email pair requires a digit
    let has_colon = text.contains(':');
    let has_digit = text.chars().any(|c| c.is_ascii_digit());

    // 1. "Label: value" -- checked first so its label wins over a generic pattern
    if has_colon {
        for (lab, res) in &p.label_prefix_res {
            for rx in res {
                for r in rx.find_iter(text) {
                    let m = match r {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    if *lab == "NAME" {
                        let from = char_offset_back(text, m.start(), 30);
                        let before = text[from..m.start()].to_lowercase();
                        if p.org_label_context_re.is_match(&before) {
                            continue;
                        }
                    }
                    let mut start = m.end();
                    while start < text.len() && matches!(text.as_bytes()[start], b' ' | b'\t' | b':' | b'.' | b'-') {
                        start += 1;
                    }
                    let mut end = text.len();
                    if *lab == "NAME" {
                        // several fields in one cell: "Patient: Jane Doe DOB: ..."
                        if let Some(stop) = p.field_stop_re.find_at(text, start) {
                            end = stop.start;
                        }
                        // 60-char cap (bytes here, chars in Python -- ASCII equivalent)
                        if end.saturating_sub(start) > 60 {
                            end = floor_boundary(text, start + 60);
                        }
                    }
                    if start < end {
                        spans.push(Span { start, end, label: lab });
                    }
                }
            }
        }
    }

    // 2. value regexes (digit-gated patterns cannot match digit-free cells)
    for (label, rx, needs_digit) in &p.patterns {
        if *needs_digit && !has_digit {
            continue;
        }
        for m in rx.find_iter(text) {
            if m.end > m.start {
                if *label == "NUMBER" && crate::patterns::is_date_like(&text[m.start..m.end]) {
                    continue; // 2023-10-04 is a date, not an identifier
                }
                spans.push(Span { start: m.start, end: m.end, label });
            }
        }
    }

    if ocr_mode {
        for (label, rx, min_digits) in &p.ocr_patterns {
            for r in rx.find_iter(text) {
                let m = match r {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let hit = &text[m.start()..m.end()];
                if digit_count(hit) >= *min_digits {
                    spans.push(Span { start: m.start(), end: m.end(), label });
                }
            }
        }
    }

    // 3. contextual date of birth -- only the date that follows the cue
    // (DATE/MONTH_DATE/YEAR all require digits)
    if has_digit {
        let dob_cues: Vec<usize> = p
            .dob_ctx_re
            .find_iter(text)
            .filter_map(|r| r.ok())
            .map(|m| m.end())
            .collect();
        for cue_end in dob_cues {
            let window_end = char_offset(text, cue_end, 30);
            let window = &text[cue_end..window_end];
            let mut taken: Vec<(usize, usize)> = Vec::new();
            for rx in [&p.date_re, &p.month_date_re, &p.year_re] {
                let Ok(Some(m)) = rx.find(window) else {
                    continue;
                };
                let start = cue_end + m.start();
                let end = cue_end + m.end();
                if taken.iter().any(|&(a, b)| start < b && end > a) {
                    continue;
                }
                taken.push((start, end));
                spans.push(Span { start, end, label: "DOB" });
            }
        }
    }

    // 4. bare mentions of a name learned from a labelled field
    for m in p.token_re.find_iter(text) {
        let low = text[m.start..m.end].to_lowercase();
        let tok = strip_dots(&low);
        if tok.chars().count() >= 3 && known_names.contains(tok) {
            spans.push(Span { start: m.start, end: m.end, label: "NAME" });
        }
    }

    // 5. address-ish cells are dense: redact the whole cell
    // (all three tests require digits)
    if has_digit {
        if fmatch(&p.address_re, text) {
            spans.push(Span { start: 0, end: text.len(), label: "ADDRESS" });
        } else if fmatch(&p.zip_re, text) && text.chars().count() <= 40 && has_state_abbr(text) {
            spans.push(Span { start: 0, end: text.len(), label: "ADDRESS" });
        } else if p.address_frag_re.is_match(text.trim()) && has_street_word(text) {
            spans.push(Span { start: 0, end: text.len(), label: "ADDRESS" });
        }
    }

    // 6. salutations and signature lines
    spans.extend(person_context_spans(text));

    // 7. person-name candidates
    spans.extend(name_spans(text, known_names, name_freq));

    merge_spans(spans)
}

// ---------------------------------------------------------------------
// Learning pass: names and their cross-document frequency.
// ---------------------------------------------------------------------

fn harvest_tokens(text: &str, learned: &mut KnownNames) {
    let p = patterns();
    for m in p.token_re.find_iter(text) {
        let low = text[m.start..m.end].to_lowercase();
        let w = strip_dots(&low);
        if w.chars().count() >= 3
            && !p.name_stop.contains(w)
            && !p.org_markers.contains(w)
        {
            learned.insert(w.to_string());
        }
    }
}

fn harvest_emails(text: &str, learned: &mut KnownNames) {
    let p = patterns();
    static SPLIT: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let split = SPLIT.get_or_init(|| regex::Regex::new(r"[._+%-]").unwrap());
    for m in p.email_re.find_iter(text) {
        let local = text[m.start()..m.end()].split('@').next().unwrap_or("");
        let parts: Vec<&str> = split.split(local).filter(|s| !s.is_empty()).collect();
        if parts.len() < 2 {
            continue; // "billing@" is not a person
        }
        for part in parts {
            let low = part.to_lowercase();
            if low.chars().all(|c| c.is_ascii_alphabetic())
                && low.chars().count() >= 3
                && !p.name_stop.contains(low.as_str())
                && !p.org_markers.contains(low.as_str())
            {
                learned.insert(low);
            }
        }
    }
}

/// Harvest name tokens from explicitly labelled name fields
/// (detect.learn_names_from_labels).
pub fn learn_names_from_labels(cell_lists: &[&[Cell]]) -> KnownNames {
    let p = patterns();
    let mut learned: KnownNames = KnownNames::new();

    for &cells in cell_lists {
        for idx in 0..cells.len() {
            let cell = &cells[idx];
            let w0 = &cell.words[0];
            if label_only(&cell.text) == Some("NAME") {
                // value cells sit on the same line to the right, or in the
                // block directly underneath the label
                for (j, c) in cells.iter().enumerate() {
                    if j == idx || c.text.trim().is_empty() {
                        continue;
                    }
                    let w = &c.words[0];
                    let same = (w.y0 - w0.y0).abs() <= 2.0 && w.x0 > w0.x0;
                    let below =
                        (-1.0..=70.0).contains(&(w.y0 - w0.y1)) && (-6.0..=300.0).contains(&(w.x0 - w0.x0));
                    if (same || below) && label_only(&c.text).is_none() {
                        harvest_tokens(&c.text, &mut learned);
                    }
                }
                continue;
            }
            // label-prefix harvest: those patterns all require a colon
            if cell.text.contains(':') {
                for (lab, res) in &p.label_prefix_res {
                    if *lab != "NAME" {
                        continue;
                    }
                    for rx in res {
                        if let Ok(Some(m)) = rx.find_from_pos(&cell.text, 0) {
                            harvest_tokens(&cell.text[m.end()..], &mut learned);
                            break;
                        }
                    }
                }
            }

            harvest_emails(&cell.text, &mut learned);
            for s in person_context_spans(&cell.text) {
                harvest_tokens(&cell.text[s.start..s.end], &mut learned);
            }
        }
    }
    learned
}

/// Count capitalised 2/3-token runs across all inputs (detect.build_name_freq).
pub fn build_name_freq(cell_lists: &[&[Cell]]) -> NameFreq {
    let p = patterns();
    let mut freq: NameFreq = NameFreq::new();

    for &cells in cell_lists {
        for cell in cells {
            let text = &cell.text;
            let toks: Vec<(usize, usize)> = p
                .token_re
                .find_iter(text)
                .iter()
                .map(|m| (m.start, m.end))
                .collect();
            let mut i = 0usize;
            while i < toks.len() {
                let mut j = i;
                while j + 1 < toks.len() && p.gap_ok_re.is_match(&text[toks[j].1..toks[j + 1].0]) {
                    j += 1;
                }
                let mut caprun: Vec<usize> = Vec::new();
                for k in i..=j {
                    let t = &text[toks[k].0..toks[k].1];
                    if t.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) || py_isupper(t) {
                        caprun.push(k);
                    } else {
                        break;
                    }
                }
                if caprun.len() >= 2 {
                    let lower: Vec<String> = caprun
                        .iter()
                        .map(|&k| strip_dots(&text[toks[k].0..toks[k].1].to_lowercase()).to_string())
                        .collect();
                    let lower_ref: Vec<&str> = lower.iter().map(|w| w.as_str()).collect();
                    for k in [2usize, 3usize] {
                        if lower_ref.len() < k {
                            continue;
                        }
                        for s in 0..=(lower_ref.len() - k) {
                            let win = &lower_ref[s..s + k];
                            if win.iter().any(|w| p.org_markers.contains(w)) {
                                continue;
                            }
                            if win.iter().all(|w| p.name_stop.contains(w)) {
                                continue;
                            }
                            if !win.iter().any(|w| !p.name_stop.contains(w) && w.len() >= 2) {
                                continue;
                            }
                            *freq.entry(win.join(" ")).or_insert(0) += 1;
                        }
                    }
                }
                i = std::cmp::max(j + 1, i + 1);
            }
        }
    }
    freq
}

/// Read an optional allowlist-of-names file (detect.load_names).
pub fn load_names(path: Option<&Path>) -> io::Result<KnownNames> {
    let mut names = KnownNames::new();
    let Some(path) = path else {
        return Ok(names);
    };
    let content = std::fs::read_to_string(path).unwrap_or_default();
    let p = patterns();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        for m in p.token_re.find_iter(line) {
            names.insert(strip_dots(&line[m.start..m.end].to_lowercase()).to_string());
        }
    }
    Ok(names)
}
