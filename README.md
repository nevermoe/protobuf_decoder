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
    
    
## Burp Plugin
You can also use this script as a burp plugin:

1. Copy `parse.py` to your burpsuite's jar directory.
2. Open burp, load `protobuf_decoder.py` as a burp extension.
3. All is done! You are now able to view protobuf binary in json format. You can also modify the value to what you want! But donnot modify the keys unless you know what you are doing.

## Explanation:
![img1](https://www.nevermoe.com/wp-content/uploads/2016/10/スクリーンショット-2016-10-13-15.05.04.png)
![img2](https://www.nevermoe.com/wp-content/uploads/2016/10/スクリーンショット-2016-10-13-15.05.24.png)

Note the keys of this json file is in the format of `field_number:id:type`. `field_number` is exactly the `field_number` in .proto file while  `id` has no meaning. It's just a field that helps to de-duplicate the keys in json.

