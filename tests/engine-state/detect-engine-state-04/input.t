>>>
POST /upload.cgi HTTP/1.1
Host: www.server.lan
Content-Type: multipart/form-data; boundary=---------------------------277531038314945
Content-Length: 385

-----------------------------277531038314945
Content-Disposition: form-data; name="uploadfile_0"; filename="AAAApicture1.jpg"
Content-Type: image/jpeg


>>>
file
>>>
content
-----------------------------277531038314945

>>>
Content-Disposition: form-data; name="uploadfile_1"; filename="BBBBpicture2.jpg"
Content-Type: image/jpeg

filecontent2
-----------------------------277531038314945--
<<<