#!/bin/bash
for dir in "include" "src" "tools"; do
    pushd "${dir}" &>/dev/null
    find . \
        -type f \
        \( -name "*.c" -o -name "*.h" \) \
        -exec clang-format -i '{}' \;
    popd &>/dev/null
done
