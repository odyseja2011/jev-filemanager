#!/usr/bin/env bash
# Verifies, ON THE REAL TARGET DATASET, that a file created by the migration copy primitive
#   1. inherits the destination directory's ACL/permission policy, and
#   2. does NOT carry over the source file's owner/mode/ACL.
#
# Usage:  scripts/verify_acl_inheritance.sh /mnt/data/MEDIA_LIBRARY/MOVIES [/path/on/source/dataset]
#
# It only creates and removes its own scratch files (names contain "migrator-acl-check").
# Run it as the same user who will run the generated batches.  It is NOT part of the Python
# application; nothing in the migrator ever executes it.
set -uo pipefail

dest_dir="${1:?destination directory (on the target dataset) required}"
src_dir="${2:-$(mktemp -d)}"
tag="migrator-acl-check-$$"
src="$src_dir/$tag.src"
tmp="$dest_dir/.$tag.partial"
final="$dest_dir/$tag.final"
rc=0

cleanup() { rm -- "$src" "$tmp" "$final" 2>/dev/null; }
trap cleanup EXIT

printf 'acl-check\n' > "$src" || { echo "cannot create $src"; exit 2; }
chmod 0600 "$src"                                  # deliberately unlike the destination policy

echo "== destination directory ACL/permissions =="
if command -v nfs4xdr_getfacl >/dev/null 2>&1; then nfs4xdr_getfacl "$dest_dir"
elif command -v getfacl >/dev/null 2>&1; then getfacl -p "$dest_dir"
else ls -ld "$dest_dir"; fi

# Exactly the primitives used by the generated scripts:
cp --reflink=auto --no-preserve=all -- "$src" "$tmp" || { echo "cp failed"; exit 2; }
ln -T -- "$tmp" "$final" || { echo "ln failed (does the filesystem support hard links?)"; exit 2; }
rm -- "$tmp"

echo
echo "== source file =="
ls -l "$src"
echo "== migrated file =="
ls -l "$final"
if command -v nfs4xdr_getfacl >/dev/null 2>&1; then nfs4xdr_getfacl "$final"
elif command -v getfacl >/dev/null 2>&1; then getfacl -p "$final"; fi

mode_src=$(stat -c %a "$src"); mode_dst=$(stat -c %a "$final")
echo
echo "source mode: $mode_src   migrated mode: $mode_dst"
if [[ "$mode_dst" == "$mode_src" && "$mode_src" == 600 ]]; then
    echo "WARNING: the migrated file has the source's 0600 mode; verify this is really the destination policy"
    rc=1
fi
echo
echo "Compare the migrated file's ACL above with what a file created directly in $dest_dir gets"
echo "(e.g. run: touch \"$dest_dir/$tag.ref\"; getfacl / nfs4xdr_getfacl it; rm it)."
echo "If they differ, adjust the copy primitive in src/migrator/batches.py BEFORE production use:"
echo "ACL inheritance correctness takes precedence over reflink optimization."
exit $rc
