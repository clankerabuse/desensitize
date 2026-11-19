//! PDF layout helpers: turn a page's words into gap-separated "cells".
//!
//! Port of src/desensitize/layout.py. Reports are tables: a label and its
//! value share a line but sit far apart -- grouping words by (block, line)
//! and splitting on wide horizontal gaps gives one cell per table column.

use std::collections::BTreeMap;

use crate::ffi::Word;

pub const DEFAULT_GAP: f32 = 16.0;

#[derive(Clone, Debug)]
pub struct Cell {
    pub words: Vec<Word>,
    pub text: String,
}

struct LineGroup {
    ws: Vec<Word>,
    y0: f32,
    y1: f32,
}

/// Group words into cells (layout.cells_from_words). Works for both native
/// text words and OCR words -- clustering only assumes horizontal lines.
pub fn cells_from_words(words: Vec<Word>, gap_threshold: f32) -> Vec<Cell> {
    if words.is_empty() {
        return Vec::new();
    }

    // group by (block, line)
    let mut by_line: BTreeMap<(i32, i32), Vec<Word>> = BTreeMap::new();
    for w in words {
        by_line.entry((w.block, w.line)).or_default().push(w);
    }

    let mut lines: Vec<LineGroup> = Vec::new();
    for ws in by_line.values() {
        let mut ws = ws.clone();
        ws.sort_by(|a, b| a.x0.partial_cmp(&b.x0).unwrap().then(a.no.cmp(&b.no)));
        let y0 = ws.iter().map(|w| w.y0).fold(f32::INFINITY, f32::min);
        let y1 = ws.iter().map(|w| w.y1).fold(f32::NEG_INFINITY, f32::max);
        lines.push(LineGroup { ws, y0, y1 });
    }
    lines.sort_by(|a, b| {
        a.y0.partial_cmp(&b.y0)
            .unwrap()
            .then(a.ws[0].x0.partial_cmp(&b.ws[0].x0).unwrap())
    });

    // merge visually-identical lines (tesseract's line numbers are unreliable)
    let mut merged: Vec<LineGroup> = Vec::new();
    for line in lines {
        if let Some(prev) = merged.last_mut() {
            let h_prev = prev.y1 - prev.y0;
            let h_line = line.y1 - line.y0;
            let mid_prev = (prev.y0 + prev.y1) / 2.0;
            let mid_line = (line.y0 + line.y1) / 2.0;
            if (mid_prev - mid_line).abs() <= 2.0
                && (3.0..=40.0).contains(&h_prev)
                && (3.0..=40.0).contains(&h_line)
            {
                prev.ws.extend(line.ws);
                prev.y0 = prev.y0.min(line.y0);
                prev.y1 = prev.y1.max(line.y1);
                continue;
            }
        }
        merged.push(line);
    }

    // split each line on wide horizontal gaps
    let mut groups: Vec<Vec<Word>> = Vec::new();
    for line in merged {
        let mut ws = line.ws;
        ws.sort_by(|a, b| a.x0.partial_cmp(&b.x0).unwrap().then(a.no.cmp(&b.no)));
        let mut cur: Vec<Word> = Vec::new();
        let mut prev_x1: Option<f32> = None;
        for w in ws {
            if !cur.is_empty() {
                if let Some(px1) = prev_x1 {
                    if w.x0 - px1 > gap_threshold {
                        groups.push(cur);
                        cur = Vec::new();
                    }
                }
            }
            prev_x1 = Some(w.x1);
            cur.push(w);
        }
        if !cur.is_empty() {
            groups.push(cur);
        }
    }

    groups
        .into_iter()
        .map(|ws| {
            let text = ws
                .iter()
                .map(|w| w.text.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            Cell { words: ws, text }
        })
        .collect()
}

/// Map a span (byte offsets) in the joined cell text back to its words
/// (layout.words_for_span). Words were joined with single spaces.
pub fn words_for_span(cell_words: &[Word], text_len: usize, start: usize, end: usize) -> Vec<Word> {
    let _ = text_len;
    let mut picked = Vec::new();
    let mut pos = 0usize;
    for w in cell_words {
        let wlen = w.text.len();
        let wstart = pos;
        let wend = pos + wlen;
        if wend > start && wstart < end {
            picked.push(w.clone());
        }
        pos = wend + 1;
    }
    picked
}
