app [main!] { pf: platform "../platform/main.roc" }

import pf.Stdout
import pf.Path
import pf.Arg exposing [Arg]

# Exercises the Path-aliased offset IO functions. File.set_len!,
# File.write_bytes_at! and File.read_bytes_at! wrap these and are covered in
# file.roc, but the exposed-function check looks for each module name on its
# own, so the Path entry points need a reference here too. This test
# self-verifies and has no expect script, so it is checked by exit code.
main! : List Arg => Result {} _
main! = |_args|
    sparse = Path.from_str("test_path_offset_io.bin")

    # set_len! on a missing file creates it at the requested size as sparse zeros.
    Path.set_len!(sparse, 256)?

    # write_bytes_at! writes at an offset without moving a seek position.
    Path.write_bytes_at!([0xAA, 0xBB, 0xCC], 100, sparse)?

    # read_bytes_at! reads that window back.
    window = Path.read_bytes_at!(sparse, 100, 3)?

    Path.delete!(sparse)?

    if window != [0xAA, 0xBB, 0xCC] then
        Err(OffsetIoMismatch(window))
    else
        Stdout.line!("Path offset IO round-trip works.")
