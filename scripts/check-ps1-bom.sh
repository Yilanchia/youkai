#!/usr/bin/env bash
# PowerShell 5.1 (the Windows default) reads a .ps1 without a BOM as the local
# OEM codepage (GBK on zh-CN machines), which turns every UTF-8 Chinese string in
# our scripts into mojibake and breaks the parser. So every .ps1 in this repo MUST
# start with a UTF-8 BOM (EF BB BF). This guard fails if any does not.
#
# Fix a offender with:  printf '\xef\xbb\xbf' | cat - f.ps1 > t && mv t f.ps1
set -euo pipefail
bad=0
while IFS= read -r f; do
  head3=$(head -c3 "$f" | xxd -p)
  if [ "$head3" != "efbbbf" ]; then
    echo "::error:: $f has no UTF-8 BOM (PowerShell 5.1 will mojibake its Chinese)"
    bad=1
  fi
done < <(find . -name '*.ps1' -not -path './.git/*')
if [ "$bad" = "0" ]; then echo "all .ps1 files carry a UTF-8 BOM"; fi
exit $bad
