# Frame AI-SAST report

`frame-ai-sast.md` is the technical report (Jekyll front-matter, ready for
lambdasec.github.io). Figures live in `assets/`.

Regenerate the charts from the committed ground truth + verdict caches:

```bash
pip install matplotlib
python benchmarks/endor_corpus/report/gen_figures.py     # rewrites assets/fig2..fig6 .png
```

`assets/figdata.json` holds the numbers the charts are built from;
`assets/fig1_architecture.svg` is hand-authored.
