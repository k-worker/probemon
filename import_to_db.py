#!env python
# we're screwing around too much with overly-specific python
# scripts to visualize different things. Let's just dump
# this into a proper database so we can use other tools,
# and have more flexible python visualization scripts that
# just read a database rather than load/parse json each time

import argparse
import sqlite3
import base64
import psycopg2

from probe_record import ProbeRecord

'''
=== initial schema ===

Observations:
id - *
timestamp - (timestamp/datetime type?)
rssi - (signed int)
GPS - (location type/split coordinate floats? probably use PostGIS for this)
MAC - FK (string)
SSID - FK (0-32 bytes)

PsuedoDevice:
MAC - * (string)
SSID - * (0-32 bytes)
Mac Info - String

MAC and SSID in PsuedoDevice are a composite key, and
the foreign key to them in the Observations table makes
linking them to particular observations quick.

Also, using them as primary keys makes selecting based on them
fast.
'''

def create_tables(conn):
	# create the tables we require
	# TODO: look at PostGIS for storing GPS location of record
	with conn.cursor() as cur:
		observations_table = '''CREATE TABLE IF NOT EXISTS observations
		(
			observation_id SERIAL NOT NULL,
			timestamp TIMESTAMPTZ,
			rssi INTEGER,
			mac CHAR(18),
			ssid BYTEA,
			PRIMARY KEY(observation_id)
		);
		'''
		psuedo_device_table = '''CREATE TABLE IF NOT EXISTS psuedo_devices
		(
			mac CHAR(18) NOT NULL,
			ssid BYTEA NOT NULL,
			mac_info TEXT,
			PRIMARY KEY (mac, ssid)
		);
		'''
		cur.execute(observations_table)
		cur.execute(psuedo_device_table)
		conn.commit()

def drop_tables(conn):
	with conn.cursor() as cur:
		cur.execute('DROP TABLE IF EXISTS observations, psuedo_devices;')
		conn.commit()

if __name__=='__main__':
	# TODO: add usage
	parser = argparse.ArgumentParser()
	parser.add_argument('inputs', nargs='+', type=argparse.FileType('r'),
		help='one or more log files to read as input')
	# TODO: add time-rebasing arg
	# TODO: add table-dropping arg

	args = parser.parse_args()

	print "Reading log file(s)"
	records = ProbeRecord.from_files(args.inputs)

	# TODO: read db credentials from file?
	conn = psycopg2.connect(database='probemonitor', user='probemonitor', password='devpassword')
	with conn:
		create_tables(conn)
	# TODO: apply time correction if requested

	# TODO: dump records into db
	with conn:
		with conn.cursor() as curs:
			# just one for now, to make sure the types fit
			#r = records[0]
			print "Inserting {} recorded probes".format(len(records))
			redundant_pseudo_devices = 0
			for r in records:
				curs.execute("INSERT INTO observations (timestamp, rssi, mac, ssid) VALUES (%s,%s,%s,%s);",
					(r.log_time, r.rssi, r.mac, psycopg2.Binary(r.ssid)) )

	# dedupe psuedodevice info, then insert so we can avoid the painful overhead
	# of a transaction for every single insert.
	psuedo_devices = {}
	for r in records:
		psuedo_devices[(r.mac, r.ssid, r.mac_info)] = 1

	with conn:
		with conn.cursor() as curs:
			print "Inserting de-duped psuedo_device records"
			for k in psuedo_devices.keys():
				curs.execute("INSERT INTO psuedo_devices (mac, ssid, mac_info) VALUES (%s,%s,%s);",
					(k[0], psycopg2.Binary(k[1]), k[2]) )
