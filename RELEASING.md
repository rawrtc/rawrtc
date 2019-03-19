# Release Process

Signing key: https://lgrahl.de/pub/pgp-key.txt

1. Set variables:

   ```bash
   export VERSION=<version>
   export GPG_KEY=3FDB14868A2B36D638F3C495F98FBED10482ABA6
   ```

2. Update version number in `meson.build` and `CHANGELOG.md`. Also, update the
   URL with the corresponding tags.

3. Do a signed commit and signed tag of the release:

   ```bash
   git add meson.build CHANGELOG.md
   git commit -S${GPG_KEY} -m "Release v${VERSION}"
   git tag -u ${GPG_KEY} -m "Release v${VERSION}" v${VERSION}
   ```

4. Push.

   ```bash
   git push && git push --tags
   ```

5. Create a new release on GitHub.

6. Prepare CHANGELOG.md for upcoming changes:

   ```md
    ## [Unreleased] (YYYY-MM-DD)

    * ...
   ```

7. Pat yourself on the back and celebrate!
