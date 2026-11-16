A BDAT command declaring more octets than max-bdat-chunk-len allows. The
transaction is closed so that parsing resumes, and the message after the
impossible declaration must still be inspected.
