Check the engine analysis output for `transform_result`: each rule's engine
carries a `transform_result` match whose `mode` is the keyword's argument,
next to the from_base64 transform, while `absent` keeps its own object with
`mode: "only"`.
