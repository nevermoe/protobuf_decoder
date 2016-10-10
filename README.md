# protobuf-decoder

This is a protobuf-decoder which can decode protobuf binary file without .proto files.

## Have a try

1. `protoc -I=. --python_out=. addressbook.proto`
2. `python write_msg.py ADDRESS_BOOK_FILE`

    Enter a telephone number and press <Enter> twice. Now you have a protobuf binary file called ADDRESS_BOOK_FILE.
3. `python parse.py ADDRESS_BOOK_FILE`

    Now you can see the decoded field looks like:
    
    ```
(1) embedded message:
	  (1) string: わたし
	  (2) Varint: 1234
	  (4) 64-bit: 0x3ff3ba5e353f7cee / 1.233000
	  (5) embedded message:
	  	(1) string: 0800000
	  	(3) embedded message:
		  	(1) 32-bit: 0x4426b1ba / 666.776978
	  (5) embedded message:
		  (1) string: 0800000
(2) 32-bit: 0x4048f5c3 / 3.140000    
    ```
    You can compare this result with the google's official `decode_raw` result using `cat ADDRESS_BOOK_FILE | protoc --decode_raw`
    
    
## TODO
1. Allow modify and re-encoding
2. Integrate to Burp
