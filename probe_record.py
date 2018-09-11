#!env python
# define a record class to hold an observed wifi probe record
# this can be the beginning to us using a database of some sort

import json
import base64

import dateutil.parser
import dateutil.tz

class ProbeRecord:
	# maybe overkill initially, but at least we have attributes to make things easy
	def __init__(self, log_time, mac, mac_info, ssid, rssi):
		# TODO: enforce types
		# TODO: explore saving tzinfo during capture, so we don't hack it in later

		obs_time = dateutil.parser.parse(log_time) # parse ISO8601 time
		if not obs_time.tzinfo:
			# if log_time has no timezone data with it, assume our local timezone (ew)
			# this works so long as I'm confined to observing/analyzing in one timezone,
			# but will (ideally) be fixed once capturing devices have accurate time
			# and tz set from GPS
			obs_time = obs_time.replace(tzinfo=dateutil.tz.tzlocal())

		self.log_time = obs_time
		self.mac = mac
		self.mac_info = mac_info
		self.ssid = ssid # ought to be 'bytes'... future python3 upgrade?
		self.rssi = rssi

	@classmethod
	def from_json_string(cls, string):
		# NOTE: we've seen log files ending in null bytes... minor file corruption?
		# NOTE: by spec, wifi SSIDs are 0-32 bytes, no encoding specified.
		try:
			j = json.loads(string)
			return cls(j['log_time'], j['mac'], j['mac_info'], base64.b64decode(j['ssid']), j['rssi'])
		except ValueError as e:
			print "{} on input {}, repr: {}".format(e, string, repr(string))

	@classmethod
	def from_file(cls, filename):
		# create a list of ProbeRecord objects from a single file
		records = []
		for l in filename:
			r = cls.from_json_string(l)
			if r:
				records.append(r)
		return records

	@classmethod
	def from_files(cls, filenames):
		# iterate over the lines in the given file, create a ProbeRecord for each,
		# then return the full list
		records = []
		for n in filenames:
			records.extend(cls.from_file(n))

		return records
