app [main!] { 
    pf: platform "../platform/main.roc",
    json: "https://github.com/lukewilliamboswell/roc-json/releases/download/0.13.0/RqendgZw5e1RsQa3kFhgtnMP8efWoqGRsAvubx4-zus.tar.br",
}

import pf.Stdout
import pf.File
import pf.Arg exposing [Arg]
import pf.Cmd
import json.Json

main! : List Arg => Result {} _
main! = |_args|
    when run_tests!({}) is
        Ok(_) ->
            cleanup_test_files!(FilesNeedToExist)
        Err(err) ->
            _ = cleanup_test_files!(FilesMaybeExist)
            Err(Exit(1, "Test run failed:\n\t${Inspect.to_str(err)}"))

run_tests! : {} => Result {} _
run_tests! = |{}|
    Stdout.line!("Testing some File functions...")?
    Stdout.line!("This will create and manipulate test files in the current directory.")?
    Stdout.line!("")?

    # Test basic file operations
    test_basic_file_operations!({})?
    
    # Test file type checking
    test_file_type_checking!({})?
    
    # Test file reader with capacity
    test_file_reader_with_capacity!({})?

    # Test hard link creation
    test_hard_link!({})?

    # Test file rename
    test_file_rename!({})?

    # Test file exists
    test_file_exists!({})?

    # Test set_len + write_bytes_at (the chunked-upload primitives)
    test_set_len_and_write_bytes_at!({})?

    Stdout.line!("\nI ran all file function tests.")

test_basic_file_operations! : {} => Result {} _
test_basic_file_operations! = |{}|
    Stdout.line!("Testing File.write_bytes! and File.read_bytes!:")?

    test_bytes = [72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100, 33] # "Hello, World!" in bytes
    File.write_bytes!(test_bytes, "test_bytes.txt")?

    file_content_bytes = File.read_bytes!("test_bytes.txt")?
    Stdout.line!("Bytes in test_bytes.txt: ${Inspect.to_str(file_content_bytes)}")?


    Stdout.line!("\nTesting File.write!:")?

    File.write!({ some: "json stuff" }, "test_write.json", Json.utf8)?
    json_file_content = File.read_utf8!("test_write.json")?
    Stdout.line!("Content of test_write.json: ${json_file_content}")?

    Ok({})

test_file_type_checking! : {} => Result {} _
test_file_type_checking! = |{}|

    Stdout.line!("\nTesting File.is_file!:")?
    is_file_result = File.is_file!("test_bytes.txt")?
    expect_true!(is_file_result, "test_bytes.txt is confirmed to be a file")?


    Stdout.line!("\nTesting File.is_sym_link!:")?
    is_symlink_one = File.is_sym_link!("test_bytes.txt")?
    expect_true!(!is_symlink_one, "test_bytes.txt is not a symbolic link")?

    Cmd.exec!("ln",["-s", "test_bytes.txt","test_symlink.txt"])?

    is_symlink_two = File.is_sym_link!("test_symlink.txt")?
    expect_true!(is_symlink_two, "test_symlink.txt is a symbolic link")?


    Stdout.line!("\nTesting File.type!:")?

    file_type_file = File.type!("test_bytes.txt")?
    Stdout.line!("test_bytes.txt file type: ${Inspect.to_str(file_type_file)}")?

    file_type_dir = File.type!(".")?
    Stdout.line!(". file type: ${Inspect.to_str(file_type_dir)}")?

    file_type_symlink = File.type!("test_symlink.txt")?
    Stdout.line!("test_symlink.txt file type: ${Inspect.to_str(file_type_symlink)}")?

    Ok({})

test_file_reader_with_capacity! : {} => Result {} _
test_file_reader_with_capacity! = |{}|
    Stdout.line!("\nTesting File.open_reader_with_capacity!:")?
    
    # First, create a multi-line test file
    multi_line_content = "First line\nSecond line\nThird line\n"
    File.write_utf8!(multi_line_content, "test_multiline.txt")?
    
    # Open reader with custom capacity
    reader_buf_size = 3
    reader = File.open_reader_with_capacity!("test_multiline.txt", reader_buf_size)?
    Stdout.line!("✓ Successfully opened reader with ${Num.to_str(reader_buf_size)} byte capacity")?
    
    # Read lines one by one
    Stdout.line!("\nReading lines from file:")?
    line1_bytes = File.read_line!(reader)?
    line1_str = Str.from_utf8(line1_bytes) ? |_| LineOneInvalidUtf8
    Stdout.line!("Line 1: ${line1_str}")?
    
    line2_bytes = File.read_line!(reader)?
    line2_str = Str.from_utf8(line2_bytes) ? |_| LineTwoInvalidUtf8
    Stdout.line!("Line 2: ${line2_str}")?

    Ok({})

test_hard_link! : {} => Result {} _
test_hard_link! = |{}|
    Stdout.line!("\nTesting File.hard_link!:")?

    # Create original file
    File.write_utf8!("Original file content for hard link test", "test_original_file.txt")?

    # Create hard link
    File.hard_link!("test_original_file.txt", "test_link_to_original.txt")
        |> Result.map_err(|err| FailedExpectation("✗ Hard link creation failed: ${Inspect.to_str(err)}"))?
    Stdout.line!("✓ Successfully created hard link: test_link_to_original.txt")?

    ls_li_output =
        Cmd.new("ls")
        |> Cmd.args(["-li", "test_original_file.txt", "test_link_to_original.txt"])
        |> Cmd.exec_output!()?

    inodes =
        Str.split_on(ls_li_output.stdout_utf8, "\n")
        |> List.map(|line|
                        Str.split_on(line, " ")
                        |> List.take_first(1)
                    )

    first_inode = List.get(inodes, 0) ? |_| FirstInodeNotFound
    second_inode = List.get(inodes, 1) ? |_| SecondInodeNotFound

    expect_true!(first_inode == second_inode, "Hard link has same inode as original")?

    # Verify both files exist and have same content
    original_content = File.read_utf8!("test_original_file.txt")?
    link_content = File.read_utf8!("test_link_to_original.txt")?

    expect_true!(original_content == link_content, "Hard link contains same content as original")?

    Ok({})

test_file_rename! : {} => Result {} _
test_file_rename! = |{}|
    Stdout.line!("\nTesting File.rename!:")?

    # Create original file
    original_name = "test_rename_original.txt"
    new_name = "test_rename_new.txt"
    File.write_utf8!("Content for rename test", original_name)?

    # Rename the file
    File.rename!(original_name, new_name)
        |> Result.map_err(|err| FailedExpectation("✗ File rename failed: ${Inspect.to_str(err)}"))?
    Stdout.line!("✓ Successfully renamed ${original_name} to ${new_name}")?

    # Verify original file no longer exists
    original_exists_after =
        when File.is_file!(original_name) is
            Ok(exists) -> exists
            Err(_) -> Bool.false

    expect_true!(!original_exists_after, "Original file ${original_name} no longer exists")?

    # Verify new file exists and has correct content
    new_exists = File.is_file!(new_name)?
    expect_true!(new_exists, "Renamed file ${new_name} exists")?

    content = File.read_utf8!(new_name)?
    expect_true!(content == "Content for rename test", "Renamed file has correct content")?

    Ok({})

test_file_exists! : {} => Result {} _
test_file_exists! = |{}|
    Stdout.line!("\nTesting File.exists!:")?

    # Test that a file that exists returns true
    filename = "test_exists.txt"
    File.write_utf8!("", filename)?

    test_file_exists = File.exists!(filename) ? FileExistsCheckFailed
    expect_true!(test_file_exists, "File.exists! returns true for a file that exists")?

    # Test that a file that does not exist returns false
    File.delete!(filename)?

    test_file_exists_after_delete = File.exists!(filename) ? FileExistsCheckAfterDeleteFailed
    expect_true!(!test_file_exists_after_delete, "File.exists! returns false for a file that does not exist")?

    Ok({})

expect_true! : Bool, Str => Result {} [FailedExpectation Str]
expect_true! = |cond, message|
    if cond then
        # Stdout failure isn't an assertion failure; drop it so we don't
        # report "I couldn't print" as "the code under test is wrong".
        Stdout.line!("✓ ${message}") |> Result.with_default({})
        Ok({})
    else
        Err(FailedExpectation("✗ ${message}"))

test_set_len_and_write_bytes_at! : {} => Result {} _
test_set_len_and_write_bytes_at! = |{}|
    Stdout.line!("\nTesting File.set_len! and File.write_bytes_at!:")?

    sparse_path = "test_sparse.bin"

    # set_len on a missing file creates it at the requested size.
    File.set_len!(sparse_path, 65536)?

    size_after_create = File.size_in_bytes!(sparse_path)?
    expect_true!(
        size_after_create == 65536,
        "File.set_len! created a 64 KiB file (size = ${Num.to_str(size_after_create)})",
    )?

    # Drop three bytes at offset 100. The rest of the file should remain zeros.
    File.write_bytes_at!([0xAA, 0xBB, 0xCC], 100, sparse_path)?

    contents = File.read_bytes!(sparse_path)?
    expect_true!(
        List.len(contents) == 65536,
        "File.write_bytes_at! preserved file size (got ${Num.to_str(List.len(contents))})",
    )?

    byte_99 = List.get(contents, 99) ? |_| Byte99NotFound
    byte_100 = List.get(contents, 100) ? |_| Byte100NotFound
    byte_101 = List.get(contents, 101) ? |_| Byte101NotFound
    byte_102 = List.get(contents, 102) ? |_| Byte102NotFound
    byte_103 = List.get(contents, 103) ? |_| Byte103NotFound
    expect_true!(
        byte_99 == 0 and byte_100 == 0xAA and byte_101 == 0xBB and byte_102 == 0xCC and byte_103 == 0,
        "Bytes landed at offset 100 with zeros on either side (got ${Inspect.to_str([byte_99, byte_100, byte_101, byte_102, byte_103])})",
    )?

    File.write_bytes_at!([0xDE, 0xAD], 200, sparse_path)?

    contents2 = File.read_bytes!(sparse_path)?
    byte_100_after = List.get(contents2, 100) ? |_| Byte100AfterNotFound
    byte_200 = List.get(contents2, 200) ? |_| Byte200NotFound
    byte_201 = List.get(contents2, 201) ? |_| Byte201NotFound
    expect_true!(
        byte_100_after == 0xAA and byte_200 == 0xDE and byte_201 == 0xAD,
        "Second write at offset 200 didn't disturb the first write at offset 100 (byte 100 = ${Num.to_str(byte_100_after)}, byte 200 = ${Num.to_str(byte_200)})",
    )?

    missing_path = "test_sparse_does_not_exist.bin"
    when File.write_bytes_at!([1, 2, 3], 0, missing_path) is
        Ok({}) ->
            Err(FailedExpectation("✗ write_bytes_at! unexpectedly succeeded on a non-existent file"))?
        Err(_) ->
            Stdout.line!("✓ write_bytes_at! correctly rejected a non-existent file")?

    # set_len shrinks: passing a smaller size truncates the file.
    File.set_len!(sparse_path, 150)?
    size_after_shrink = File.size_in_bytes!(sparse_path)?
    expect_true!(
        size_after_shrink == 150,
        "set_len! to a smaller size shrank the file to 150 bytes (got ${Num.to_str(size_after_shrink)})",
    )?

    # The byte at offset 100 (within the new length) survives; offset 200 is gone.
    contents3 = File.read_bytes!(sparse_path)?
    expect_true!(
        List.len(contents3) == 150,
        "Read returns exactly 150 bytes after shrink (got ${Num.to_str(List.len(contents3))})",
    )?

    byte_100_after_shrink = List.get(contents3, 100) ? |_| Byte100AfterShrinkNotFound
    expect_true!(
        byte_100_after_shrink == 0xAA,
        "Bytes within the new length survived the shrink (byte 100 = ${Num.to_str(byte_100_after_shrink)})",
    )?

    # set_len grows: extending re-introduces sparse zeros past the previous end.
    File.set_len!(sparse_path, 1024)?
    size_after_grow = File.size_in_bytes!(sparse_path)?
    expect_true!(
        size_after_grow == 1024,
        "set_len! to a larger size extended the file to 1024 bytes (got ${Num.to_str(size_after_grow)})",
    )?

    contents4 = File.read_bytes!(sparse_path)?
    byte_500 = List.get(contents4, 500) ? |_| Byte500NotFound
    expect_true!(
        byte_500 == 0,
        "Newly-extended region reads as zeros (byte 500 = ${Num.to_str(byte_500)})",
    )?

    # write_bytes_at past the current end extends the file (POSIX pwrite semantics).
    File.write_bytes_at!([0xEE, 0xFF], 2000, sparse_path)?
    size_after_extend = File.size_in_bytes!(sparse_path)?
    expect_true!(
        size_after_extend == 2002,
        "write_bytes_at! past EOF extended the file to 2002 bytes (got ${Num.to_str(size_after_extend)})",
    )?

    contents5 = File.read_bytes!(sparse_path)?
    byte_2000 = List.get(contents5, 2000) ? |_| Byte2000NotFound
    byte_2001 = List.get(contents5, 2001) ? |_| Byte2001NotFound
    byte_1500 = List.get(contents5, 1500) ? |_| Byte1500NotFound
    expect_true!(
        byte_2000 == 0xEE and byte_2001 == 0xFF and byte_1500 == 0,
        "Past-EOF write landed at offset 2000, gap zero-filled (byte 1500 = ${Num.to_str(byte_1500)}, byte 2000 = ${Num.to_str(byte_2000)}, byte 2001 = ${Num.to_str(byte_2001)})",
    )?

    # write_bytes_at with an empty byte list is a no-op.
    size_before_empty = File.size_in_bytes!(sparse_path)?
    File.write_bytes_at!([], 500, sparse_path)?
    size_after_empty = File.size_in_bytes!(sparse_path)?
    expect_true!(
        size_before_empty == size_after_empty,
        "write_bytes_at! with an empty byte list is a no-op (was ${Num.to_str(size_before_empty)}, now ${Num.to_str(size_after_empty)})",
    )?

    # set_len on a brand-new file followed by read returns all zeros (pure sparse).
    pure_sparse_path = "test_pure_sparse.bin"
    File.set_len!(pure_sparse_path, 256)?
    sparse_contents = File.read_bytes!(pure_sparse_path)?
    all_zero =
        sparse_contents
        |> List.all(|b| b == 0)
    expect_true!(
        List.len(sparse_contents) == 256 and all_zero,
        "Pure-sparse set_len! read returns 256 zero bytes (len = ${Num.to_str(List.len(sparse_contents))}, all_zero = ${Inspect.to_str(all_zero)})",
    )?
    File.delete!(pure_sparse_path)?

    # read_bytes_at: read a 3-byte window at offset 100 (where 0xAA, 0xBB, 0xCC live).
    window = File.read_bytes_at!(sparse_path, 100, 3)?
    expect_true!(
        window == [0xAA, 0xBB, 0xCC],
        "read_bytes_at! returned the 3 bytes at offset 100 (got ${Inspect.to_str(window)})",
    )?

    # read_bytes_at past the end of the file errors (pread short-read).
    when File.read_bytes_at!(sparse_path, 1_000_000, 10) is
        Ok(_) -> Err(FailedExpectation("✗ read_bytes_at! past EOF unexpectedly succeeded"))?
        Err(_) -> Stdout.line!("✓ read_bytes_at! past EOF errored")?

    Ok({})

cleanup_test_files! : [FilesNeedToExist, FilesMaybeExist] => Result {} _
cleanup_test_files! = |files_requirement|
    Stdout.line!("\nCleaning up test files...")?

    test_files = [
        "test_bytes.txt",
        "test_symlink.txt",
        "test_write.json",
        "test_multiline.txt",
        "test_original_file.txt",
        "test_link_to_original.txt",
        "test_rename_new.txt",
        "test_sparse.bin",
    ]

    delete_result = List.for_each_try!(
        test_files,
        |filename| File.delete!(filename)
    )
    
    when files_requirement is
        FilesNeedToExist ->
            delete_result ? FileDeletionFailed
            
        FilesMaybeExist ->
            Ok({})?

    Stdout.line!("✓ Deleted all files.")

