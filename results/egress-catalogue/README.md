# Local egress-catalogue output

This path is the default destination for catalogue tables and figures generated
from synthetic examples or researcher-supplied inputs. The output directory is:

```text
results/egress-catalogue/generated/
```

It is intentionally ignored. No findings, published outputs, or output hash
manifest are part of the methods repository. Use `RESULTS_DIR=/another/path`
with `make demo-egress` or `make analyze-egress` to write elsewhere.
