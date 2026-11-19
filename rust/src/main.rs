//! desens-rs: PII-redacted, agent-friendly copies of PDFs.
//!
//! Rust milestone 1 of the desens rewrite: full text-layer pipeline (the
//! same MuPDF core the Python build uses), destructive glyph redaction,
//! metadata scrub, annotation scrub, and the self-check re-read.
//!
//! Exit codes (the contract, same as the Python build):
//!     0  clean: copies written, self-check found nothing
//!     1  bad usage / missing input / not-yet-ported option
//!     2  review needed: the self-check still sees something in the copies
//!     3  scanned input: refused rather than faked (OCR is milestone 2)

mod detect;
mod engine;
mod ffi;
mod layout;
mod patterns;
mod verify;

use std::collections::{BTreeMap, HashSet};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context};
use clap::Parser;
use rayon::prelude::*;

use detect::{build_name_freq, learn_names_from_labels, load_names, KnownNames};
use engine::{apply_and_save, safe_output_name, scrub_annots, DocumentResult, Hashes, Mark, PagePlan, Vocab};
use ffi::count_pages;
use layout::cells_from_words;
use verify::{scan_copy, VerificationReport};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn default_out() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    format!("{home}/Downloads/agent-friendly")
}

#[derive(Parser, Debug)]
#[command(
    name = "desens-rs",
    version = concat!("desens-rs ", env!("CARGO_PKG_VERSION"), " (rust milestone 1)"),
    about = "Write PII-redacted, agent-friendly copies of PDFs (SSN, address, phone, email, DOB, account IDs, names)",
)]
struct Args {
    /// PDF file(s) to copy-and-redact
    inputs: Vec<String>,
    /// output directory
    #[arg(short, long, default_value_t = default_out())]
    out: String,
    /// extra names to always redact, one per line
    #[arg(long)]
    names: Option<String>,
    /// report what would be redacted, write nothing
    #[arg(long)]
    dry_run: bool,
    /// write a JSON manifest of counts here
    #[arg(long)]
    report: Option<String>,
    /// OCR pages without a text layer (auto/force/off). This build does not
    /// OCR yet: scans are refused with exit 3.
    #[arg(long, default_value = "auto")]
    ocr: String,
    /// render resolution for OCR (accepted for compatibility; unused here)
    #[arg(long, default_value_t = 300)]
    dpi: i32,
    /// tesseract language (accepted for compatibility; unused here)
    #[arg(long, default_value = "eng")]
    ocr_lang: String,
    /// OCR words below this confidence become [UNCLEAR] (OCR: milestone 2)
    #[arg(long)]
    min_conf: Option<f32>,
    /// OCR embedded images on otherwise-textual pages. This build never OCRs
    /// images -- passing this is an error rather than a silent coverage drop.
    #[arg(long = "ocr-images")]
    ocr_images: bool,
    /// skip embedded images (this build always behaves this way; accepted silently)
    #[arg(long = "no-ocr-images")]
    no_ocr_images: bool,
    /// print each redaction mark (page, label, position)
    #[arg(long = "debug-marks")]
    debug_marks: bool,
    /// counts only, no banner
    #[arg(short, long)]
    quiet: bool,
}

fn eprint_exit(msg: String, code: u8) -> ExitCode {
    eprintln!("{msg}");
    ExitCode::from(code)
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("!! {e:#}");
            ExitCode::from(1)
        }
    }
}

struct DocPlans {
    marks: Vec<Mark>,
    counts: BTreeMap<String, usize>,
    image_blocks: usize,
    source_vocab: Vocab,
}

fn run(args: &Args) -> anyhow::Result<ExitCode> {
    if args.inputs.is_empty() {
        return Ok(eprint_exit("no input files given".to_string(), 1));
    }
    if args.ocr == "force" {
        return Ok(eprint_exit(
            "--ocr force is not implemented in the Rust build yet; use the Python build".into(),
            1,
        ));
    }
    if args.ocr != "auto" && args.ocr != "off" {
        return Ok(eprint_exit(
            format!("--ocr must be one of: auto, force, off (got {})", args.ocr),
            1,
        ));
    }
    if args.ocr_images {
        return Ok(eprint_exit(
            "--ocr-images: image OCR is not implemented in the Rust build (it never proves \
             pixels); use the Python build"
                .into(),
            1,
        ));
    }
    let inputs: Vec<PathBuf> = args.inputs.iter().map(PathBuf::from).collect();
    for p in &inputs {
        if !p.is_file() {
            return Ok(eprint_exit(format!("!! missing input: {}", p.display()), 1));
        }
    }

    // ---- Pass 1: extract every page in parallel. Each rayon worker opens
    // its own read-only MuPDF handle with its own fz_context.
    let mut extracts: Vec<Vec<PagePlan>> = Vec::new();
    for src in &inputs {
        let n = count_pages(&src.display().to_string())
            .with_context(|| format!("open {}", src.display()))?;
        let plans: Vec<anyhow::Result<PagePlan>> = (0..n)
            .into_par_iter()
            .map(|pno| {
                let ex = ffi::extract_page(&src.display().to_string(), pno)?;
                // a page with almost no words is a scan (layout.page_needs_ocr)
                let ocr_mode = ex.words.len() < 5;
                let cells = cells_from_words(ex.words, engine::DEFAULT_GAP);
                Ok(PagePlan {
                    cells,
                    ocr_mode,
                    text: ex.text,
                    image_blocks: ex.image_blocks,
                })
            })
            .collect();
        let mut pages = Vec::new();
        for r in plans {
            pages.push(r?);
        }
        extracts.push(pages);
    }

    // ---- scan refusal: the pixel proof needs OCR (milestone 2 of this
    // port), so refuse rather than fake. A page with neither words nor
    // images is a genuinely blank sheet and stays clean, like Python.
    for (src, pages) in inputs.iter().zip(&extracts) {
        let scan_pages: Vec<String> = pages
            .iter()
            .enumerate()
            .filter(|(_, p)| p.ocr_mode && p.image_blocks > 0)
            .map(|(i, _)| (i + 1).to_string())
            .collect();
        if !scan_pages.is_empty() {
            return Ok(eprint_exit(
                format!(
                    "!! {}: page(s) {} have no text layer (scanned PDF). This Rust build does \
                     not OCR yet -- refusing rather than pretending it is redacted; run the \
                     Python build for scans.",
                    src.display(),
                    scan_pages.join(", ")
                ),
                3,
            ));
        }
    }

    // ---- Pass 2: name learning across every page of every input.
    let cell_lists: Vec<&[layout::Cell]> = extracts
        .iter()
        .flat_map(|pages| pages.iter().map(|p| p.cells.as_slice()))
        .collect();
    let mut known_names: KnownNames = load_names(args.names.as_deref().map(Path::new))?;
    known_names.extend(learn_names_from_labels(&cell_lists));
    let name_freq = build_name_freq(&cell_lists);

    // ---- Pass 3: plan marks per document.
    let mut all_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut hashes: Hashes = Hashes::new();
    let mut vocab: Vocab = HashSet::new();
    let mut documents: Vec<DocumentResult> = Vec::new();
    let mut plans: Vec<DocPlans> = Vec::new();

    for (src, pages) in inputs.iter().zip(&extracts) {
        let mut marks: Vec<Mark> = Vec::new();
        let mut doc_counts: BTreeMap<String, usize> = BTreeMap::new();
        for (pno, plan) in pages.iter().enumerate() {
            engine::plan_page(
                pno as i32,
                &plan.cells,
                &known_names,
                &name_freq,
                plan.ocr_mode,
                80.0, // POLICY min_conf (only used in ocr_mode)
                &mut marks,
                &mut hashes,
                &mut doc_counts,
                &mut vocab,
                args.debug_marks,
            );
        }
        let image_blocks: usize = pages.iter().map(|p| p.image_blocks.max(0) as usize).sum();
        let joined = pages
            .iter()
            .map(|p| p.text.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let source_vocab = engine::tokens(&joined);
        documents.push(DocumentResult {
            file_name: src
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default(),
            pages: pages.len(),
            output: None,
            counts: BTreeMap::new(),
            mode: "text",
            ocr_pages: 0,
            image_regions: 0,
            unreadable_pages: Vec::new(),
            image_blocks,
        });
        plans.push(DocPlans { marks, counts: doc_counts, image_blocks, source_vocab });
    }

    // ---- dry run: plan only, write nothing.
    if args.dry_run {
        for (doc, plan) in documents.iter_mut().zip(&plans) {
            doc.counts = plan.counts.clone();
            println!("  {}: {} pages", doc.file_name, doc.pages);
            for (cat, n) in &plan.counts {
                println!("      {cat:<9} {n}");
            }
        }
        let total: usize = plans.iter().map(|p| p.counts.values().sum::<usize>()).sum();
        println!("  would redact {total} spans; nothing written (--dry-run)");
        return Ok(ExitCode::SUCCESS);
    }

    // ---- Pass 4: apply, save, verify.
    let out_dir = PathBuf::from(&args.out);
    std::fs::create_dir_all(&out_dir).with_context(|| format!("create {}", out_dir.display()))?;
    let _ = std::fs::set_permissions(&out_dir, std::fs::Permissions::from_mode(0o700));

    let mut verifications: Vec<(String, VerificationReport)> = Vec::new();
    let mut clean = true;

    for i in 0..inputs.len() {
        let src = &inputs[i];
        let out_path = out_dir.join(safe_output_name(src));
        let write = ffi::WriteDoc::open(&src.display().to_string())?;
        let pages = write.count_pages()?;

        // split DocPlans into disjoint field borrows
        let DocPlans {
            marks,
            counts,
            source_vocab,
            ..
        } = &mut plans[i];

        // annotation scrub first (annot indices shift once redact annots exist)
        let mut scrub_counts = std::mem::take(counts);
        let _rewritten = scrub_annots(&write, pages, &known_names, &name_freq, &mut hashes, &mut scrub_counts)?;
        *counts = scrub_counts;

        let mut by_page: BTreeMap<i32, Vec<(Vec<ffi::Word>, &'static str)>> = BTreeMap::new();
        for m in marks.iter() {
            by_page.entry(m.page).or_default().push((m.words.clone(), m.label));
        }
        apply_and_save(&write, pages, &by_page, &out_path)?;
        drop(write);
        std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod {}", out_path.display()))?;

        let rep = scan_copy(
            &out_path.display().to_string(),
            &hashes,
            &vocab,
            25,
            Some(source_vocab),
        )?;
        clean &= rep.clean();
        documents[i].output = Some(out_path);
        verifications.push((documents[i].file_name.clone(), rep));
    }

    // aggregate counts
    for (doc, plan) in documents.iter_mut().zip(&plans) {
        doc.counts = plan.counts.clone();
        for (k, v) in &plan.counts {
            *all_counts.entry(k.clone()).or_insert(0) += v;
        }
    }
    let total: usize = all_counts.values().sum();

    // ---- summary (counts only, never values) ----
    if !args.quiet {
        println!(
            "== redaction summary (rust milestone 1: text-layer proof; counts only, no values) =="
        );
        for doc in &documents {
            let out = doc
                .output
                .as_ref()
                .map(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default())
                .unwrap_or_default();
            println!("  {}  ->  {}   ({} pages, {})", doc.file_name, out, doc.pages, doc.mode);
            for (cat, n) in &doc.counts {
                println!("      {cat:<9} {n}");
            }
        }
        println!("== self-check on the copies ==");
    }
    for (name, rep) in &verifications {
        if !args.quiet {
            let hits: Vec<String> = rep
                .pattern_hits
                .iter()
                .filter(|(_, &v)| v > 0)
                .map(|(k, v)| format!("{k}: {v}"))
                .collect();
            let hits = if hits.is_empty() { "none".to_string() } else { format!("{{{}}}", hits.join(", ")) };
            println!("  {name}");
            println!("    residual pattern hits: {hits}");
            println!("    residual re-detected known values: {}", rep.leak_total);
            for (cat, len, masked) in &rep.masked_samples {
                println!("      {cat:<9} {len:>3}  {masked}");
            }
        }
    }

    let images_total: usize = documents.iter().map(|d| d.image_blocks).sum();
    if !args.quiet {
        let images_note = if images_total > 0 {
            format!(" ({images_total} image(s) present in this run)")
        } else {
            String::new()
        };
        println!(
            "  caveats (rust milestone 1): scans are refused (exit 3); embedded images are \
             not OCR-proven{images_note}; annotation titles and file attachments are not \
             checked; form-field values are checked but never rewritten. The Python build \
             covers all of these today."
        );
        println!("  RESULT: {}", if clean { "CLEAN" } else { "REVIEW NEEDED (see above)" });
    }

    // ---- JSON manifest ----
    if let Some(report) = &args.report {
        let manifest = serde_json::json!({
            "tool": format!("desens-rs {VERSION} (rust milestone 1)"),
            "coverage": "text layer + annotation contents/subject + metadata; no OCR, no image regions",
            "inputs": inputs.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            "outputs": documents.iter().map(|d| d.as_dict()).collect::<Vec<_>>(),
            "redactions_total": total,
            "redactions_by_type": all_counts,
            "verification": verifications
                .iter()
                .map(|(n, r)| (n.clone(), r.as_dict()))
                .collect::<std::collections::BTreeMap<_, _>>(),
            "caveats": [
                "scans refused (OCR is milestone 2)",
                format!("embedded images not OCR-proven ({images_total} present)"),
                "annotation titles and attachments not checked",
                "form-field values checked but not rewritten",
            ],
            "clean": clean,
        });
        let path = PathBuf::from(report);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        std::fs::write(&path, serde_json::to_string_pretty(&manifest)?)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(if clean { ExitCode::SUCCESS } else { ExitCode::from(2) })
}
