# Papers

Everything written for submission, with the LaTeX sources. Each Overleaf zip is the same source as the folder
next to it, ready to upload (Overleaf: New Project, Upload Project, pick the zip; compiler pdfLaTeX).

| Folder | What | Compiled | Overleaf |
|---|---|---|---|
| `final_report/` | Final report: course cover page, then the paper in IEEE conference format (IEEEtran), 18 references | `TriageGuard_final_report.pdf` | `TriageGuard_final_report_overleaf.zip`, main document `main.tex` |
| `progress_report/` | Progress evaluation report, its demo script (`DEMO.md`) and slide deck | `TriageGuard_progress_report.pdf` | `TriageGuard_progress_report_overleaf.zip`, main document `main.tex` |
| `literature_survey/` | Literature survey (20 works, the course's table format) | `TriageGuard_literature_survey.pdf` | source is `progress_report/literature_survey.tex` (shares the survey rows with the progress report) |

`final_report/Final_Report_Template.docx` is the course template the final report follows.

## Final report layout

```
final_report/
  main.tex              loads the cover page and the sections
  refs.bib              references (IEEE style via IEEEtran.bst)
  sections/
    cover.tex           course cover page (fill in the red fields: faculty, emails in main.tex)
    00_abstract.tex
    01_introduction.tex background, problem, gap, objectives O1-O7, contributions
    02_related.tex      related work and the comparison table
    03_methodology.tex  architecture, dataset, preprocessing, algorithms, design choices, setup, metrics
    04_results.tex      results and discussion
    05_conclusion.tex   conclusion, limitations, future work
  figures/              dashboard screenshots (all diagrams and charts are TikZ/pgfplots in the .tex)
```

Every table in the final report is followed or preceded by a short "Why" paragraph explaining what it contains
and why those items were chosen, and Section III ("Design choices and their rationale") lists every fixed value
in the pipeline with the reason for it and whether a standard or we set it. The formulas and their sources are
also in [`docs/FORMULAS.md`](../docs/FORMULAS.md).

## Rebuild locally

```bash
cd papers/final_report
pdflatex main && bibtex main && pdflatex main && pdflatex main
```
