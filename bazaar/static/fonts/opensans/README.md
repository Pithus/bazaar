font from https://github.com/FontFaceKit/open-sans

We cloned the repository then copied all font files in this directory:

```bash
git clone https://github.com/FontFaceKit/open-sans.git
for f in $(find open-sans -type f \( -name '*.ttf' -o -name '*.woff' -o -name '*.svg' -o -name '*.ttf' -o -name '*.woff2' \)); do cp $f ./; done
rm -Rf open-sans
```

