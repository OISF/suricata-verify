# lua-file-store-id-htp-multipart

Evidence that `File::file_store_id` -
exposed as `file_id()` on the lua file handle - is available in a
multi-file scenario: one HTTP/1.1 flow whose request is a multipart/form-data upload
with two file parts (htp's mime file extraction is
request-direction). The file-store
output (the filedata path in output-filedata.c) assigns a unique
non-zero file_store_id to each file it stores, and the lua file
output script reads `file_id()` for both files: the check requires
two lines with distinct non-zero ids.

Caveat pinned by the config: the id is only assigned on the filedata
store path (file-store output enabled and the file subject to
storing); with that output disabled the id stays 0 by design.
