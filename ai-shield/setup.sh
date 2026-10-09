#!/bin/bash
# OCR files extension/lib me copy karta hai (MV3 me remote scripts allowed nahi)
set -e
mkdir -p tmp && cd tmp && npm init -y >/dev/null && npm i tesseract.js@5 tesseract.js-core@5 @tesseract.js-data/eng@1 >/dev/null
cp node_modules/tesseract.js/dist/tesseract.min.js node_modules/tesseract.js/dist/worker.min.js ../extension/lib/
cp node_modules/tesseract.js-core/tesseract-core*.js node_modules/tesseract.js-core/tesseract-core*.wasm ../extension/lib/
cp node_modules/@tesseract.js-data/eng/4.0.0_best_int/eng.traineddata.gz ../extension/lib/
cd .. && rm -rf tmp && echo "OCR files ready"
