# -*- coding: utf-8 -*-
#! /usr/bin/python

import addressbook_pb2
import sys

# This function fills in a Person message based on user input.
def PromptForAddress(person):
  #person.id = int(raw_input("Enter person ID number: "))
  #person.name = raw_input("Enter name: ")
  person.id = 1234
  person.name = "わたし"
  person.num = 1.233

  #email = raw_input("Enter email address (blank for none): ")
  #if email != "":
  #  person.email = email

  while True:
    number = raw_input("Enter a phone number (or leave blank to finish): ")
    if number == "":
      break

    phone_number = person.phone.add()
    phone_number.number = number
    account = phone_number.account.fnum = 666.777

    phone_number2 = person.phone.add()
    phone_number2.number = number

    #type = raw_input("Is this a mobile, home, or work phone? ")
    if type == "mobile":
      phone_number.type = addressbook_pb2.Person.MOBILE
      phone_number2.type = addressbook_pb2.Person.MOBILE
    else:
      print "Unknown phone type; leaving as default value."

# Main procedure:  Reads the entire address book from a file,
#   adds one person based on user input, then writes it back out to the same
#   file.
if len(sys.argv) != 2:
  print "Usage:", sys.argv[0], "ADDRESS_BOOK_FILE"
  sys.exit(-1)

address_book = addressbook_pb2.AddressBook()

# Read the existing address book.
try:
  f = open(sys.argv[1], "rb")
  address_book.ParseFromString(f.read())
  f.close()
except IOError:
  print sys.argv[1] + ": Could not open file.  Creating a new one."

# Add an address.
address_book.fnum = 3.14
PromptForAddress(address_book.person.add())

# Write the new address book back to disk.
f = open(sys.argv[1], "wb")
f.write(address_book.SerializeToString())
f.close()
