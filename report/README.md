# Progress evaluation report (Overleaf)

LaTeX source for the progress evaluation report, structured around the evaluation rubric
(problem and objectives, design, implementation, testing, presentation).

```
main.tex              IEEE conference layout, loads the sections below
literature_survey.tex standalone literature survey (A2 landscape, teacher's table format, 20 works)
sections/             01_problem, 02_design, 03_implementation, 04_testing, 05_presentation, appendix,
                      appendix_survey, survey_rows (the survey rows, shared by both documents)
refs.bib              references
figures/              dashboard screenshots (all diagrams are TikZ inside the .tex files)
```

## Upload to Overleaf

1. Zip this `report/` folder (or use the zip shared in the project).
2. Overleaf: New Project, Upload Project, pick the zip.
3. Menu: Compiler pdfLaTeX, Main document `main.tex` (or `literature_survey.tex` for the survey on its own). Recompile.

## Still to fill in

- Section V-C: who did what (shown in red in the PDF).

Every number comes from `results/`, `docs/HOW_IT_WORKS.md` and the README. The synthetic ground-truth
numbers (Table VI) come from `python samples/make_synthetic.py` followed by
`python -m triageguard analyze samples/synthetic.raw --no-llm`.
