#!/usr/bin/env python

import sys
from string import replace
import os
import datetime
# import logging


RanapFile = sys.argv[1]
RanapDir = '/srv/ranap_analazer/'
RanapTempFile = 'ranap_temp.pcap'
TxtTempFile = 'RanapFields.txt'
SessionLogfile = RanapDir+'logs/session.log'
NotFoundLogFile = RanapDir+'logs/NotFound.log'
OutputLogFile = RanapDir+'logs/out.log'
EcxepFile = RanapDir+'logs/Except.log'

TsharkDoing = True

try:
	sys.argv[1] == True 
	if sys.argv[1].lower() == "test":
		TxtTempFile = 'RanapTempFields.txt'
		TsharkDoing = False
		print("\n ****** Use temp file RanapTempFields.txt *****") 
		
except IndexError:
	print("Add ranap file in argument!")
	sys.exit()

ListTsharkFilter = [
	'gsm_a.dtap.msg_gmm_type == 0x01',	#GPRS attach request
	'ranap.procedureCode == 15',		#CommonID
	'gsm_a.dtap.msg_gmm_type == 0x02',	#GPRS attach accept
	'gsm_a.dtap.msg_gmm_type == 0x04',	#GPRS attach reject
	'gsm_a.dtap.msg_gmm_type == 0x13',	#Authentification Response
	'gsm_a.dtap.msg_gmm_type == 0x1c',	#Authentification Failure
	'gsm_a.dtap.msg_gmm_type == 0x12',	#Authentification Req
	'gsm_a.dtap.msg_gmm_type == 0x15',	#Identity request
	'gsm_a.dtap.msg_gmm_type == 0x16',	#Identity Response
	'ranap.procedureCode == 6',			#SecurityModeControl
	'gsm_a.dtap.msg_gmm_type == 0x03', 	#Attach complete
	'gsm_a.dtap.msg_gmm_type == 0x05', 	#Detach request
	'gsm_a.dtap.msg_gmm_type == 0x06',	#Detach accept
	'ranap.procedureCode == 1', 			#Iu-release
	'ranap.procedureCode == 11' 			#Iu-release request
]

TypeFields = [
	'frame.time_epoch',
	'gsm_a.dtap.msg_gmm_type',
	'sccp.message_type',
	'ranap.procedureCode',
	'ranap.RANAP_PDU',
	'sccp.slr',
	'sccp.dlr',
	'gsm_a.imsi',
	'gsm_a.tmsi',
	'gsm_a.gm.gmm.cause',
	'ranap.imsi_digits',
	'ranap.radioNetwork'
]
MyDelim = "-"

CutListFields = ['epoch', 'type_pack' ,'gmm_type', 'mess_type', 'procCode', 'ran_pdu', 'slr', 'dlr', 'imsi',  'tmsi', 'cause', 'imsi_digits']

countspas=[15, 10, 8, 9, 9, 7, 8, 8 ,15, 10, 5, 15]

class RanapRecord(object):

	def __init__(self):
		self.epoch 				= None
		self.msg_gmm_type 		= None
		self.message_type 		= None
 		self.procedureCode 		= None
 		self.pdu 				= None
		self.slr 				= None
		self.dlr 				= None
		self.imsi 				= None
		self.tmsi 				= None
		self.cause 				= None
		self.imsi_digits		= None
		self.type_pack			= None
		self.radioNetwork		= None
		
		super(RanapRecord, self).__init__()
	
	def parse_string(self, line):

		m=line.split("#")
		self.epoch = "%.3f" % float(m[0])
		self.msg_gmm_type = m[1]
		self.message_type = m[2]
		self.procedureCode = m[3]
		self.pdu = m[4]
		self.slr = m[5]
		self.dlr = m[6]
		self.imsi = m[7]
		self.tmsi = m[8]
		self.cause = m[9]
		self.imsi_digits = m[10]
		self.radioNetwork = m[11][:-1]
		self.type_pack = self.type_of_packet()
		# ranap.radioNetwork

	def type_of_packet(self):
		if self.msg_gmm_type == "0x01"  : return 'ATTreq'
		elif self.msg_gmm_type == "0x15": return 'IdnReq'
		elif self.msg_gmm_type == "0x16": return 'IdnRes'
		elif self.msg_gmm_type == "0x12": return 'AutReq'
		elif self.msg_gmm_type == "0x13": return 'AutRes'
		elif self.msg_gmm_type == "0x1c": return 'AutFai'
		elif self.msg_gmm_type == "0x02": return 'ATTacc'
		elif self.msg_gmm_type == "0x03": return 'ATTcom'
		elif self.msg_gmm_type == "0x04": return 'ATTrej'
		elif self.msg_gmm_type == "0x05": return 'DETreq'
		elif self.msg_gmm_type == "0x06": return 'DETacc'
		elif self.procedureCode == "15":  return 'CommID'
		elif self.procedureCode == "6":
			if   self.pdu == "0": return 'SecIni'
			elif self.pdu == "1": return 'SecSuc'
			elif self.pdu == "2": return 'SecUns'
		elif self.procedureCode == "1":
			if   self.pdu == "0": return 'IuRIni'
			elif self.pdu == "1": return 'IuRSuc'
			elif self.pdu == "2": return 'IuRUns'
		elif self.procedureCode == "11":
			if   self.pdu == "0": return 'IuRreq'
			# elif self.pdu == "1": return 'IuRSuc'
		else : return '...'

	def __repr__(self):
		out = ''
		out += "|" + self.epoch.ljust(countspas[0])
		out += "|" + self.type_pack.ljust(countspas[1])
		out += "|" + self.msg_gmm_type.center(countspas[2])
		out += "|" + self.message_type.center(countspas[3])
		out += "|" + self.procedureCode.center(countspas[4])
		out += "|" + self.pdu.center(countspas[5])
		out += "|" + self.slr.ljust(countspas[6])
		out += "|" + self.dlr.ljust(countspas[7])
		out += "|" + self.imsi.ljust(countspas[8])
		out += "|" + self.tmsi.ljust(countspas[9])
		out += "|" + self.cause.ljust(countspas[10])
		out += "|" + self.imsi_digits.ljust(countspas[11])
		
		return out

	def __str__(self):
		return repr(self)


def main():
	# logging.basicConfig(format = u'%(message)s', level = logging.INFO, filename = logfile)

	os.system("cp /dev/null "+SessionLogfile)
	os.system("cp /dev/null "+NotFoundLogFile)
	os.system("cp /dev/null "+EcxepFile)
	os.system("cp /dev/null "+OutputLogFile)

	StatAttach = 0
	StatDetach = 0
	StatAccept = 0
	StatReject = 0

	CompleteSession = 0

	if TsharkDoing:

		TsharkFilter = (' || ').join(ListTsharkFilter)
		os.system("""tshark -r {1} -Y '{2}' -w {0}{3}""".format(RanapDir, RanapFile, TsharkFilter, RanapTempFile)) 

		TypeFilter = (' -e ').join(TypeFields)
		os.system("""tshark -r {0}{2} -Tfields -e {1} -E separator='#' > {3}""".format(RanapDir, TypeFilter, RanapTempFile, TxtTempFile)) 
	
	FirstLine = ''
	for rr in CutListFields: 
		FirstLine += "|" + rr.center(countspas[CutListFields.index(rr)])

	AttaSess = {}
	DB = {}
	ExcepSes = []
	
	with open(RanapDir+TxtTempFile) as trace:
		strings = trace.readlines()

		with open(OutputLogFile, 'a') as writerOut:
			writerOut.write(FirstLine+"\n")
			writerOut.write('-' * len(FirstLine)+"\n")
	
			for m_line in strings:
				ll=RanapRecord()
				ll.parse_string(m_line)
		
				# print(ll)
				writerOut.write(str(ll)+"\n")

				with open(SessionLogfile, 'a') as writer: 

					try:
						# if ll.message_type == "0x02": DB[ll.slr]=ll.dlr

						if ll.type_pack == "ATTreq":
							AttaSess[ll.slr] = {'imsi':ll.imsi, 'StrSes':ll.type_pack, 'date':float(ll.epoch), 'att_cause':'', 'aut_cause':'', 'last_mess':''} 
							# if ll.message_type == "0x01": AttaSess[ll.slr] = {'imsi':ll.imsi, 'StrSes':ll.type_pack, 'date':float(ll.epoch), 'att_cause':'', 'aut_cause':'', 'last_mess':''} 
							# else : AttaSess[ll.dlr] = {'imsi':ll.imsi, 'StrSes':ll.type_pack, 'date':float(ll.epoch), 'att_cause':'', 'aut_cause':'', 'last_mess':''} 
							StatAttach += 1

						elif ll.type_pack == "IdnReq":
							DiffTime = float(ll.epoch) - AttaSess[ll.dlr]['date']
							AttaSess[ll.dlr]['StrSes'] += MyDelim + ll.type_pack +'(' + "%.3f" % DiffTime + ")"
							# AttaSess[ll.dlr]['last_mess'] = ll.type_pack

							if AttaSess.has_key(ll.dlr) : DB[ll.slr]=ll.dlr

						elif ll.type_pack == "IdnRes":
							DiffTime = float(ll.epoch) - AttaSess[DB[ll.dlr]]['date']
							AttaSess[DB[ll.dlr]]['StrSes'] += MyDelim + ll.type_pack +'(' + "%.3f" % DiffTime + ")"
							if ll.imsi != "" : AttaSess[DB[ll.dlr]]['imsi'] = ll.imsi
							# AttaSess[DB[ll.dlr]]['last_mess'] = ll.type_pack

						elif ll.type_pack == "CommID":
							DiffTime = float(ll.epoch)-AttaSess[ll.dlr]['date']
							AttaSess[ll.dlr]['StrSes'] += MyDelim + ll.type_pack +'(' + "%.3f" % DiffTime + ")"
							# AttaSess[ll.dlr]['last_mess'] = ll.type_pack
							if ll.message_type == "0x02":
								AttaSess[ll.dlr]['imsi'] = ll.imsi_digits

								if AttaSess.has_key(ll.dlr) : DB[ll.slr]=ll.dlr

						elif ll.type_pack == "SecIni":
							DiffTime = float(ll.epoch)-AttaSess[ll.dlr]['date']
							AttaSess[ll.dlr]['StrSes'] += MyDelim + ll.type_pack +'(' + "%.3f" % DiffTime + ")"
							# AttaSess[ll.dlr]['last_mess'] = ll.type_pack

						elif ll.type_pack == "SecSuc":
							DiffTime = float(ll.epoch)-AttaSess[DB[ll.dlr]]['date']
							AttaSess[DB[ll.dlr]]['StrSes'] += MyDelim + ll.type_pack +'(' + "%.3f" % DiffTime + ")"
							# AttaSess[DB[ll.dlr]]['last_mess'] = ll.type_pack

						elif ll.type_pack == "SecUns":
							DiffTime = float(ll.epoch)-AttaSess[DB[ll.dlr]]['date']
							AttaSess[DB[ll.dlr]]['StrSes'] += MyDelim + ll.type_pack +'(' + "%.3f" % DiffTime + ")"
							# AttaSess[ll.dlr]['last_mess'] = ll.type_pack

						elif ll.type_pack == "AutReq":
							DiffTime = float(ll.epoch)-AttaSess[ll.dlr]['date']
							AttaSess[ll.dlr]['StrSes'] += MyDelim + ll.type_pack +'(' + "%.3f" % DiffTime + ")"
							# AttaSess[ll.dlr]['last_mess'] = ll.type_pack

						elif ll.type_pack == "AutRes":
							DiffTime = float(ll.epoch)-AttaSess[DB[ll.dlr]]['date']
							AttaSess[DB[ll.dlr]]['StrSes'] += MyDelim + ll.type_pack +'(' + "%.3f" % DiffTime + ")"
							# AttaSess[DB[ll.dlr]]['last_mess'] = ll.type_pack

						elif ll.type_pack == "IuRreq":
							DiffTime = float(ll.epoch)-AttaSess[DB[ll.dlr]]['date']
							AttaSess[DB[ll.dlr]]['StrSes'] += MyDelim + ll.type_pack +'(' + "%.3f" % DiffTime + ")"
							AttaSess[DB[ll.dlr]]['aut_cause']=ll.radioNetwork
							# AttaSess[DB[ll.dlr]]['last_mess'] = ll.type_pack

						elif ll.type_pack == "AutFai":
							DiffTime = float(ll.epoch)-AttaSess[DB[ll.dlr]]['date']
							AttaSess[DB[ll.dlr]]['StrSes'] += MyDelim + ll.type_pack +'(' + "%.3f" % DiffTime + ")"
							AttaSess[DB[ll.dlr]]['aut_cause']=ll.cause
							# AttaSess[DB[ll.dlr]]['last_mess'] = ll.type_pack

						elif ll.type_pack == "ATTacc":
							DiffTime = float(ll.epoch)-AttaSess[ll.dlr]['date']
							AttaSess[ll.dlr]['StrSes'] += MyDelim + ll.type_pack +'(' + "%.3f" % DiffTime + ")"
							# AttaSess[ll.dlr]['last_mess'] = ll.type_pack

							StatAccept += 1

						elif ll.type_pack  == "ATTrej":
							DiffTime = float(ll.epoch)-AttaSess[ll.dlr]['date']
							AttaSess[ll.dlr]['StrSes'] += MyDelim + ll.type_pack +'(' + "%.3f" % DiffTime + ")"
							AttaSess[ll.dlr]['att_cause']=ll.cause
							# AttaSess[ll.dlr]['last_mess'] = ll.type_pack

							StatReject +=1
							if AttaSess.has_key(ll.dlr)  and ll.slr!='' : DB[ll.slr]=ll.dlr

						elif ll.type_pack  == "ATTcom":
							DiffTime = float(ll.epoch)-AttaSess[DB[ll.dlr]]['date']
							AttaSess[DB[ll.dlr]]['StrSes'] += MyDelim + ll.type_pack +'(' + "%.3f" % DiffTime + ")"
							AttaSess[DB[ll.dlr]]['last_mess'] = ll.type_pack

						elif ll.type_pack  == "DETreq":
							# print(DB[ll.dlr])
							DiffTime = float(ll.epoch)-AttaSess[DB[ll.dlr]]['date']
							AttaSess[DB[ll.dlr]]['StrSes'] += MyDelim + ll.type_pack +'(' + "%.3f" % DiffTime + ")"
							# AttaSess[ll.dlr]['StrSes'] += MyDelim + ll.type_pack +'(' + "%.3f" % DiffTime + ")"
							# AttaSess[DB[ll.dlr]]['last_mess'] = ll.type_pack

							StatDetach += 1

						elif ll.type_pack  == "DETacc":
							DiffTime = float(ll.epoch)-AttaSess[ll.dlr]['date']
							AttaSess[ll.dlr]['StrSes'] += MyDelim + ll.type_pack +'(' + "%.3f" % DiffTime + ")"
							# AttaSess[ll.dlr]['last_mess'] = ll.type_pack

						elif ll.type_pack  == "IuRIni":
							DiffTime = float(ll.epoch)-AttaSess[ll.dlr]['date']
							AttaSess[ll.dlr]['StrSes'] += MyDelim + ll.type_pack +'(' + "%.3f" % DiffTime + ")"
							AttaSess[ll.dlr]['aut_cause']=ll.radioNetwork
							# AttaSess[ll.dlr]['last_mess'] = ll.type_pack

						elif ll.type_pack  == "IuRSuc":
							DiffTime = float(ll.epoch)-AttaSess[DB[ll.dlr]]['date']
							AttaSess[DB[ll.dlr]]['StrSes'] += MyDelim + ll.type_pack +'(' + "%.3f" % DiffTime + ")"
							# AttaSess[DB[ll.dlr]]['last_mess'] = ll.type_pack

							CompleteSession += 1

							prDate = datetime.datetime.fromtimestamp(float(AttaSess[DB[ll.dlr]]['date'])).strftime('%Y%m%d %H:%M:%S')
							writer.write("{0}#{1}#{2}#{3}#{4}#{5}\n".format(AttaSess[DB[ll.dlr]]['imsi'], prDate, ll.dlr, AttaSess[DB[ll.dlr]]['aut_cause'].ljust(3),  AttaSess[DB[ll.dlr]]['att_cause'].ljust(3), AttaSess[DB[ll.dlr]]['StrSes']))
							
							AttaSess.pop(DB[ll.dlr])
							inv_db = {v: k for k, v in DB.items()}
							DB.pop(ll.dlr)

					except KeyError: 
						pass
						# ExcepSes.append(ll)
				
				writer.close()
			writerOut.write('-' * len(FirstLine)+"\n")
		writerOut.close()
		
	with open(NotFoundLogFile, 'a') as writerNotFound:
		with open(SessionLogfile, 'a') as writer: 
			for i in AttaSess.keys(): 
				prDate = datetime.datetime.fromtimestamp(float(AttaSess[i]['date'])).strftime('%Y%m%d %H:%M:%S')
				if AttaSess[i]['last_mess'] == "ATTcom" :
					writer.write("{0}#{1}#{2}#{3}#{4}#{5}\n".format(AttaSess[i]['imsi'], prDate, i, AttaSess[i]['aut_cause'].ljust(3),  AttaSess[i]['att_cause'].ljust(3), AttaSess[i]['StrSes']))
					CompleteSession += 1
				else :
					writerNotFound.write("{0} #{1}#{2}#{3}#{4}#{5}\n".format(i, prDate, AttaSess[i]['imsi'], AttaSess[i]['aut_cause'].ljust(3),  AttaSess[i]['att_cause'].ljust(3), AttaSess[i]['StrSes']))

		writer.close()
	writerNotFound.close()


	# with open(EcxepFile, 'a') as writerExept:
	# 	for o in ExcepSes: writerExept.write(str(o)+"\n")
	# writerExept.close()

	print("StatAttach - %s") % StatAttach
	print("StatDetach - %s") % StatDetach
	print("StatAccept - %s") % StatAccept
	print("StatReject - %s") % StatReject
	
	print("\nCompleteSession - %s") % CompleteSession

	# print(len(DB))
	# print(DB)
	# print(len(inv_db))
	# print(inv_db)




	# print ''
	
	
if __name__ == '__main__':
	main()