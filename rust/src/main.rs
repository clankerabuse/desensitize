//! desens-rs: PII-redacted, agent-friendly copies of PDFs.
//!
//! Rust port of desens: full text-layer pipeline plus tesseract OCR for scans
//! and embedded-image regions (milestone 2), destructive glyph/pixel redaction
//! on the same MuPDF core the Python build uses, metadata + annotation +
//! form-field scrub, typed placeholders, invisible text layers for OCR pages,
//! and the self-check re-read including a pixel re-scan.
//!
//! Exit codes (the contract, same as the Python build):
//!     0  clean: copies written, self-check found nothing
//!     1  bad usage / missing input
//!     2  review needed: the self-check still sees something in the copies
//!     3  scanned input with --ocr off: refused rather than faked
//!     4  tesseract (or its language pack) missing

mod detect;
mod engine;
mod ffi;
mod layout;
mod ocr;
mod patterns;
mod verify;

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use clap::Parser;
use rayon::prelude::*;

use detect::{build_name_freq, learn_names_from_labels, load_names, KnownNames};
use engine::{
    apply_and_save, safe_output_name, scrub_annots, scrub_widgets, DocumentResult, Hashes, Mark,
    PagePlan, Vocab,
};
use ffi::count_pages;
use layout::cells_from_words;
use ocr::OcrUnavailable;
use verify::{ocr_rescan, scan_copy, VerificationReport};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn default_out() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    format!("{home}/Downloads/agent-friendly")
}

#[derive(Parser, Debug)]
#[command(
    name = "desens-rs",
    version = concat!("desens-rs ", env!("CARGO_PKG_VERSION")),
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
    /// OCR pages without a text layer: auto (default), force every page, or
    /// off (refuse scans)
    #[arg(long, default_value = "auto")]
    ocr: String,
    /// render resolution for OCR
    #[arg(long, default_value_t = ocr::DEFAULT_DPI)]
    dpi: i32,
    /// tesseract language
    #[arg(long, default_value = ocr::DEFAULT_LANG)]
    ocr_lang: String,
    /// OCR words below this confidence are redacted as [UNCLEAR]
    #[arg(long, default_value_t = ocr::DEFAULT_MIN_CONF)]
    min_conf: f32,
    /// OCR embedded images on otherwise-textual pages (default: on)
    #[arg(long = "ocr-images", default_value_t = true)]
    ocr_images: bool,
    /// skip embedded images: text layer only, and nothing proves what was in
    /// the pictures
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
    ocr_pages: usize,
    image_regions: usize,
    unreadable_pages: Vec<i32>,
    image_count: usize,
    /// ocr_mode pages -> None (whole page); region pages -> Some(rects)
    pixel_pages: BTreeMap<i32, Option<Vec<ffi::FzRect>>>,
    smear_pages: BTreeSet<i32>,
    pixel_words: BTreeMap<i32, Vec<ffi::Word>>,
    source_vocab: Vocab,
}

fn run(args: &Args) -> anyhow::Result<ExitCode> {
    if args.inputs.is_empty() {
        return Ok(eprint_exit("no input files given".to_string(), 1));
    }
    if args.ocr != "auto" && args.ocr != "force" && args.ocr != "off" {
        return Ok(eprint_exit(
            format!("--ocr must be one of: auto, force, off (got {})", args.ocr),
            1,
        ));
    }
    let ocr_images = args.ocr_images && !args.no_ocr_images;

    let inputs: Vec<PathBuf> = args.inputs.iter().map(PathBuf::from).collect();
    for p in &inputs {
        if !p.is_file() {
            return Ok(eprint_exit(format!("!! missing input: {}", p.display()), 1));
        }
    }

    // ---- Pass 1a: extract every page's text layer in parallel. One
    // read-only MuPDF handle + one fz_context per rayon worker.
    let mut extracts: Vec<Vec<PagePlan>> = Vec::new();
    for src in &inputs {
        let n = count_pages(&src.display().to_string())
            .with_context(|| format!("open {}", src.display()))?;
        let plans: Vec<anyhow::Result<PagePlan>> = (0..n)
            .into_par_iter()
            .map(|pno| {
                let ex = ffi::extract_page(&src.display().to_string(), pno)?;
                // a page with almost no words is a scan (layout.page_needs_ocr)
                let ocr_mode =
                    args.ocr == "force" || (args.ocr == "auto" && ex.words.len() < 5);
                let cells = cells_from_words(ex.words, engine::DEFAULT_GAP);
                Ok(PagePlan {
                    cells,
                    ocr_mode,
                    words: None,
                    regions: Vec::new(),
                    text: ex.text,
                    images: ex.images,
                })
            })
            .collect();
        let mut pages = Vec::new();
        for r in plans {
            pages.push(r?);
        }
        extracts.push(pages);
    }

    // ---- --ocr off refuses scanned input outright (engine.NoTextLayerError)
    if args.ocr == "off" {
        for (src, pages) in inputs.iter().zip(&extracts) {
            let total_chars: usize = pages.iter().map(|p| p.text.trim().chars().count()).sum();
            if total_chars < 50 {
                return Ok(eprint_exit(
                    format!(
                        "!! {}: no text layer (scanned PDF) and OCR is disabled, refusing \
                         rather than pretending it is redacted.",
                        src.display()
                    ),
                    3,
                ));
            }
        }
    }

    // ---- anything to OCR? then tesseract must be present (exit 4)
    let needs_ocr = extracts.iter().any(|pages| {
        pages.iter().any(|p| p.ocr_mode)
            || (ocr_images && pages.iter().any(|p| !p.images.is_empty()))
    });
    let tesseract: Option<PathBuf> = if needs_ocr {
        match ocr::require_tesseract(&args.ocr_lang) {
            Ok(exe) => Some(exe),
            Err(OcrUnavailable(msg)) => {
                return Ok(eprint_exit(format!("!! OCR unavailable: {msg}"), 4));
            }
        }
    } else {
        None
    };

    // ---- Pass 1b: OCR in parallel -- one single-threaded tesseract per
    // page/region task, so wall time scales with cores (OMP_THREAD_LIMIT=1).
    // PARITY NOTE: python's --ocr off leaves an image-only page in a mixed
    // doc unexamined (has_text_layer passes on the textual pages); the port
    // matches that, and --no-ocr-images carries the same "examined less"
    // semantics.
    let mut unreadable: Vec<Vec<i32>> = vec![Vec::new(); inputs.len()];
    for (doc_idx, pages) in extracts.iter_mut().enumerate() {
        let exe = tesseract.as_deref();
        let src = inputs[doc_idx].display().to_string();
        let taken: Vec<PagePlan> = std::mem::take(pages);
        let results: Vec<anyhow::Result<(PagePlan, bool)>> = taken
            .into_par_iter()
            .enumerate()
            .map(|(pno, mut plan)| -> anyhow::Result<(PagePlan, bool)> {
                let mut unreadable_page = false;
                if plan.ocr_mode {
                    let Some(exe) = exe else {
                        anyhow::bail!("internal: tesseract missing for OCR page");
                    };
                    let words = ocr::ocr_page_best(&src, pno as i32, args.dpi, &args.ocr_lang, exe)
                        .map_err(|e| anyhow::anyhow!("{}", e.0))?;
                    // group into cells while the words still read normally
                    plan.cells = cells_from_words(words.clone(), engine::DEFAULT_GAP);
                    plan.words = Some(words.clone());
                    // the input vocabulary sees the OCR words too
                    let joined = words
                        .iter()
                        .map(|w| w.text.as_str())
                        .collect::<Vec<_>>()
                        .join(" ");
                    plan.text.push('\n');
                    plan.text.push_str(&joined);
                    // a page with ink that nothing could be read from is not
                    // clean, it is unproven
                    let strong = ocr::strong_words(&words).len();
                    let ink = ffi::page_ink_fraction(&src, pno as i32);
                    if std::env::var_os("DS_DEBUG_UNREADABLE").is_some() {
                        eprintln!(
                            "[debug-unreadable] p{} strong={strong} ink={ink:.4} words={}",
                            pno + 1,
                            words.len()
                        );
                    }
                    if strong == 0 && ink > ocr::INK_FLOOR {
                        unreadable_page = true;
                    }
                } else if ocr_images && !plan.images.is_empty() {
                    let Some(exe) = exe else {
                        anyhow::bail!("internal: tesseract missing for image OCR");
                    };
                    // every picture on a text page, not just the big ones
                    let regions = ocr::image_regions(&plan.images, 1.0, (8.0, 4.0), 64, 0.0);
                    for (idx, rect) in regions.iter().enumerate() {
                        let words = ocr::ocr_region_words(
                            &src,
                            pno as i32,
                            *rect,
                            args.dpi,
                            &args.ocr_lang,
                            (idx + 1) as i32,
                            exe,
                        )?;
                        if words.is_empty() {
                            continue;
                        }
                        plan.regions.push((*rect, words.clone()));
                        plan.cells.extend(cells_from_words(words, engine::DEFAULT_GAP));
                    }
                }
                Ok((plan, unreadable_page))
            })
            .collect();
        let mut new_pages = Vec::with_capacity(results.len());
        for (pno, r) in results.into_iter().enumerate() {
            let (plan, bad) = r?;
            if bad {
                unreadable[doc_idx].push(pno as i32);
            }
            new_pages.push(plan);
        }
        *pages = new_pages;
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

    for (i, (src, pages)) in inputs.iter().zip(&extracts).enumerate() {
        let mut marks: Vec<Mark> = Vec::new();
        let mut doc_counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut pixel_pages: BTreeMap<i32, Option<Vec<ffi::FzRect>>> = BTreeMap::new();
        let mut smear_pages: BTreeSet<i32> = BTreeSet::new();
        let mut pixel_words: BTreeMap<i32, Vec<ffi::Word>> = BTreeMap::new();

        for (pno, plan) in pages.iter().enumerate() {
            engine::plan_page(
                pno as i32,
                &plan.cells,
                &known_names,
                &name_freq,
                plan.ocr_mode,
                args.min_conf,
                &mut marks,
                &mut hashes,
                &mut doc_counts,
                &mut vocab,
                args.debug_marks,
            );
            if plan.ocr_mode {
                pixel_pages.insert(pno as i32, None);
                smear_pages.insert(pno as i32);
                if let Some(words) = &plan.words {
                    let mut all = words.clone();
                    for (_, ws) in &plan.regions {
                        all.extend(ws.clone());
                    }
                    pixel_words.insert(pno as i32, all);
                }
            } else if !plan.regions.is_empty() {
                pixel_pages
                    .insert(pno as i32, Some(plan.regions.iter().map(|(r, _)| *r).collect()));
                smear_pages.insert(pno as i32);
                let mut all: Vec<ffi::Word> = Vec::new();
                for (_, ws) in &plan.regions {
                    all.extend(ws.clone());
                }
                pixel_words.insert(pno as i32, all);
            }
        }

        let ocr_pages = pages.iter().filter(|p| p.ocr_mode).count();
        let image_regions: usize = pages.iter().map(|p| p.regions.len()).sum();
        let image_count = pages.iter().map(|p| p.images.len()).sum();
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
            ocr_pages,
            image_regions,
            unreadable_pages: unreadable[i].clone(),
            image_blocks: image_count,
        });
        plans.push(DocPlans {
            marks,
            counts: doc_counts,
            ocr_pages,
            image_regions,
            unreadable_pages: unreadable[i].clone(),
            image_count,
            pixel_pages,
            smear_pages,
            pixel_words,
            source_vocab,
        });
        let _ = i;
    }

    // document mode (text | ocr | mixed), python parity
    for (doc, pages) in documents.iter_mut().zip(&extracts) {
        doc.mode = if doc.ocr_pages > 0 && doc.ocr_pages == pages.len() {
            "ocr"
        } else if doc.ocr_pages > 0 {
            "mixed"
        } else {
            "text"
        };
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

        let DocPlans {
            marks,
            counts,
            source_vocab,
            pixel_pages,
            smear_pages,
            pixel_words,
            ..
        } = &mut plans[i];

        // object scrub first (annot indices shift once redact annots exist)
        let mut scrub_counts = std::mem::take(counts);
        let _annots =
            scrub_annots(&write, pages, &known_names, &name_freq, &mut hashes, &mut scrub_counts)?;
        let _fields =
            scrub_widgets(&write, pages, &known_names, &name_freq, &mut hashes, &mut scrub_counts)?;
        *counts = scrub_counts;

        let mut by_page: BTreeMap<i32, Vec<(Vec<ffi::Word>, &'static str)>> = BTreeMap::new();
        for m in marks.iter() {
            by_page.entry(m.page).or_default().push((m.words.clone(), m.label));
        }
        apply_and_save(&write, pages, &by_page, smear_pages, pixel_words, &out_path)?;
        drop(write);
        std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod {}", out_path.display()))?;

        // verify: the text layer always, then the pixels that were OCR'd
        let mut rep = scan_copy(
            &out_path.display().to_string(),
            &hashes,
            &vocab,
            25,
            Some(source_vocab),
        )?;
        if tesseract.is_some() && !pixel_pages.is_empty() {
            let pixel = ocr_rescan(
                &out_path.display().to_string(),
                pixel_pages,
                &hashes,
                &vocab,
                25,
                Some(source_vocab),
                200, // python ocr_rescan default dpi
                &args.ocr_lang,
                tesseract.as_deref().unwrap(),
            )?;
            rep.merge(pixel);
        }
        clean &= rep.clean();
        documents[i].output = Some(out_path);
        verifications.push((documents[i].file_name.clone(), rep));
    }

    // python parity: a page nothing could be read from makes the whole run
    // unproven, whatever the self-check says
    clean &= documents.iter().all(|d| d.unreadable_pages.is_empty());

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
            "== redaction summary (full coverage + pixel proof; counts only, no values) =="
        );
        for doc in &documents {
            let out = doc
                .output
                .as_ref()
                .map(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default())
                .unwrap_or_default();
            let mut tag = String::new();
            if doc.ocr_pages > 0 {
                tag += &format!(", {} OCR page(s)", doc.ocr_pages);
            }
            if doc.image_regions > 0 {
                tag += &format!(", {} image region(s)", doc.image_regions);
            }
            println!("  {}  ->  {}   ({} pages, {}{})", doc.file_name, out, doc.pages, doc.mode, tag);
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

    // unreadable pages: the copy cannot be proven clean
    let unreadable_docs: Vec<&DocumentResult> =
        documents.iter().filter(|d| !d.unreadable_pages.is_empty()).collect();
    if !unreadable_docs.is_empty() {
        println!("  pages nothing could be read from (the copy cannot be proven clean):");
        for doc in &unreadable_docs {
            let listing = doc
                .unreadable_pages
                .iter()
                .take(12)
                .map(|p| (p + 1).to_string())
                .collect::<Vec<_>>()
                .join(", ");
            let more = if doc.unreadable_pages.len() > 12 { " ..." } else { "" };
            println!("    {}: page {listing}{more}", doc.file_name);
        }
    }

    if !args.quiet {
        if !ocr_images {
            println!(
                "  caveat: --no-ocr-images: pictures were skipped, so nothing proves what \
                 was in them"
            );
        }
        println!(
            "  caveat: annotation titles and file attachments are not checked, and outline \
             titles are checked but never rewritten (no public MuPDF API)"
        );
        println!("  RESULT: {}", if clean { "CLEAN" } else { "REVIEW NEEDED (see above)" });
    }

    // ---- JSON manifest ----
    if let Some(report) = &args.report {
        let images_total: usize = documents.iter().map(|d| d.image_blocks).sum();
        let manifest = serde_json::json!({
            "tool": format!("desens-rs {VERSION}"),
            "coverage": if ocr_images {
                "text layer + OCR pages + embedded images + pixel re-scan"
            } else {
                "text layer + OCR pages (pictures skipped via --no-ocr-images)"
            },
            "verify_deep": true,
            "inputs": inputs.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            "outputs": documents.iter().map(|d| d.as_dict()).collect::<Vec<_>>(),
            "redactions_total": total,
            "redactions_by_type": all_counts,
            "verification": verifications
                .iter()
                .map(|(n, r)| (n.clone(), r.as_dict()))
                .collect::<std::collections::BTreeMap<_, _>>(),
            "caveats": [
                "annotation titles and attachments not checkable via public MuPDF API",
                format!("images on pages: {images_total} (OCR-proven unless --no-ocr-images)"),
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
