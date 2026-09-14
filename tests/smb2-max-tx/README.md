# smb2-max-tx

Pins that `app-layer.protocols.smb.max-tx: 3` bounds the number of live
SMB2 transactions per flow and errors the flow instead of growing the
transaction list without end.

Synthetic capture: four SMB2 WRITE request records, each carrying a
fresh file GUID. Every WRITE on an unknown GUID opens a new file
transaction; the 4th WRITE cannot create one: `new_tx()` refuses and
sets `applayer/smb/too_many_transactions` on the newest transaction.

The three accepted writes are stored verbatim (100 x 0x41, 100 x 0x42,
100 x 0x43), proving the parser stayed in sync until the refusal.
