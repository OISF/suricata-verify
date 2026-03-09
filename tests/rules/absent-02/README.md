# Suricata-Verify Test: error_or option of absent keyword

## Description

This test validates the `error_or` option of the `absent` keyword functionality in Suricata. The `error_or` option matches when either:
1. A transform (like `from_base64`) fails to process the input data (error condition), OR
2. The transform succeeds and subsequent content patterns match

## Test Cases

### Test 1 (SID 1): Invalid base64 with content
- **Input**: Invalid base64 string containing "fail"
- **Expected**: Alert should fire because base64 decode fails (error condition)
- **Rule**: `http.request_body; from_base64; absent: error_or; content:"fail";`

### Test 2 (SID 2): Valid base64 with matching content
- **Input**: Valid base64 that decodes to text containing "malicious"
- **Expected**: Alert should fire because decode succeeds AND content matches
- **Rule**: `http.request_body; from_base64; absent: error_or; content:"malicious";`

### Test 3 (SID 3): Invalid base64 triggering error
- **Input**: Invalid base64 string containing "error"
- **Expected**: Alert should fire because base64 decode fails
- **Rule**: `http.request_body; from_base64; absent: error_or; content:"error";`

### Test 4 (SID 4): Valid base64 without matching content
- **Input**: Valid base64 that decodes to benign content
- **Expected**: NO alert (decode succeeds but content doesn't match)
- **Rule**: `http.request_body; from_base64; absent: error_or; content:"nomatch";`

## Generating the PCAP

Run the Python script to generate the test PCAP:

```bash
python3 generate-pcap.py
```

This requires the `scapy` Python library:

```bash
pip3 install scapy
```

## Running the Test

This test is designed to work with the suricata-verify framework:

```bash
# From the suricata-verify repository
./run.py /path/to/this/test/directory
```

## Key Behavior Tested

1. **Error Detection**: The `error_or` option correctly identifies when transforms fail
2. **Content Matching**: When transforms succeed, normal content matching proceeds
3. **OR Logic**: The keyword matches if EITHER condition is true (error OR content match)
4. **Non-Match**: The keyword doesn't match when both conditions are false

## Difference from `absent: or_else`

While `absent: or_else` checks if a buffer is NULL (absent) OR matches content, `absent: error_or`
specifically checks for transform **errors** (via the DETECT_CI_FLAGS_ERROR flag) OR content matches. This makes it ideal for detecting:
- Malformed encoded data
- Evasion attempts using invalid encodings
- Protocol violations in encoded fields
