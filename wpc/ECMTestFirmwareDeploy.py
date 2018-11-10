#!/usr/bin/env python3

import sys
import os
import json
import ftplib
from optparse import OptionParser
import tarfile
import shutil

class ECMTestFirmwareTool(object):
	def __init__(self, host, username='ecm', password='ecm', test_path=None, cust_fw_path=None):
		self.host = None
		if host != "":
			self.host = host
		self.user = username
		self.pwd = password

		self.cust_fw_path = cust_fw_path



		self.base_staging_path = os.path.join('.') # relative to where this script is running
		self.staging_path = os.path.join(self.base_staging_path, 'custom_fw_staging')

		self.test_path = None
		if test_path != "":
			self.base_test_path = test_path # relative to where this script is running
			self.test_path = os.path.join(self.base_test_path, 'dtds')


		self.wpc_tar_file = os.path.join(self.base_staging_path, 'wpc.tar.gz')
		self.cms_tar_file = os.path.join(self.base_staging_path, '..', 'service_manager', 'cms.tar.gz')

		self.platform = None
		self.version = None
		self.timestamp = None

	def ftp_rm_tree(self, session, path):
		"""Recursively delete a directory tree on a remote server."""
		wd = session.pwd()

		try:
			names = session.nlst(path)
		except ftplib.all_errors as e:
			# some FTP servers complain when you try and list non-existent paths
			print('ftp_rm_tree: Could not remove {0}: {1}'.format(path, e))
			return

		for name in names:
			if os.path.split(name)[1] in ('.', '..'):
				continue

			try:
				session.cwd(name)  # if we can cwd to it, it's a folder
				session.cwd(wd)  # don't try a nuke a folder we're in
				self.ftp_rm_tree(session, name)
			except ftplib.all_errors:
				session.delete(name)

		try:
			session.rmd(path)
		except ftplib.all_errors as e:
			print('ftp_rm_tree: Could not remove {0}: {1}'.format(path, e))


	def ftp_upload(self, session, path):
		files = os.listdir(path)
		for f in files:
			full_path = os.path.join(path, f)
			if os.path.isfile(full_path):
				fh = open(full_path, 'rb')
				session.storbinary('STOR {}'.format(f), fh)
				fh.close()
			elif os.path.isdir(full_path):
				if os.path.islink(full_path):
					continue
				session.mkd(f)
				session.cwd(f)
				self.ftp_upload(session, full_path)

		session.cwd('..')

	def create_staging_folder(self):
		try:
			shutil.rmtree(os.path.join(self.staging_path, self.platform))
		except OSError as e:
			if e.errno != 2:
				print('exception: {}'.format(e))
				raise e

		# extract to staging directory
		tar = tarfile.open(self.wpc_tar_file)
		tar.extractall(path=self.staging_path)
		tar.close()

		# extract to staging directory
		tar = tarfile.open(self.cms_tar_file)
		tar.extractall(path=self.staging_path)
		tar.close()

	def create_test_folder(self):
		if self.test_path is None:
			return

		#copy files into testing directory
		jsonmin_src = os.path.join(self.staging_path, self.platform, self.version, self.timestamp, 'service_manager', 'config_dtd.jsonmin')
		jsonmin_dst = os.path.join(self.test_path, self.platform, self.version, 'config_dtd.jsonmin')
		rinfo_src = os.path.join(self.staging_path, self.platform, self.version, self.timestamp, 'html', 'rinfo.json')
		rinfo_dst = os.path.join(self.test_path, self.platform, self.version, 'rinfo.json')

		try:
			shutil.rmtree(os.path.join(self.test_path, self.platform))
		except OSError as e:
			if e.errno != 2:
				print('exception: {}'.format(e))
				raise e

		try:
			os.makedirs(os.path.join(self.test_path, self.platform))
		except OSError as e:
			if e.errno != 17: #EEXIST
				print('could not create ecmtest_staging directory')
				raise e
		try:
			os.makedirs(os.path.join(self.test_path, self.platform, self.version))
		except OSError as e:
			if e.errno != 17: #EEXIST
				print('could not create ecmtest_staging directory')
				raise e
		try:
			shutil.copyfile(jsonmin_src, jsonmin_dst)
		except Exception as e:
			print('Exception: {0} - could not create file {1}'.format(e, rinfo_dst))
			raise e

		try:
			shutil.copyfile(rinfo_src, rinfo_dst)
		except Exception as e:
			print('Exception: {0} - could not create file {1}'.format(e, rinfo_dst))
			raise e


	def refresh(self):
		# get some specific information (platform, fw version, timestamp)
		try:
			tar = tarfile.open(self.cms_tar_file)
		except Exception as e:
			print('failed to open cms_tar_file: {}'.format(e))
			return

		names = tar.getnames()[3].split(os.sep)
		tar.close()
		self.platform = names[1]
		self.version = names[2]
		self.timestamp = names[3]

		# make sure we have a staging directory
		try:
			os.makedirs(os.path.join(self.staging_path))
		except OSError as e:
			if e.errno != 17: #EEXIST
				print('failed to create ecmtest_staging directory: {}'.format(e))
				return

		# make sure we have a test dtd directory
		if self.test_path:
			try:
				os.makedirs(os.path.join(self.test_path))
			except OSError as e:
				if e.errno != 17: #EEXIST
					print('failed to create test dtd directory: {}'.format(e))
					return

		try:
			# create platform staging sub-folder and fill
			self.create_staging_folder()
		except Exception as e:
			print('failed to create staging folder: {}'.format(e))
		else:
			try:
				# create platform test sub-folder and fill
				self.create_test_folder()
			except Exception as e:
				print('failed to create test folder: {}'.format(e))
			else:
				if self.host is None:
					return
				# upload staging platform folder and contents to cms custom firmware server
				session = ftplib.FTP(self.host, self.user, self.pwd)
				session.cwd(self.cust_fw_path)
				try:
					self.ftp_rm_tree(session, self.platform)
				except Exception as e:
					print('failed to remove ecm custom firmware product folder: {}'.format(e))
				else:
					try:
						session.mkd(self.platform)
						session.cwd(self.platform)
					except Exception as e:
						print('failed to create remote custom firmware product folder: {}'.format(e))
					else:
						try:
							self.ftp_upload(session, os.path.join(self.staging_path, self.platform))
						except Exception as e:
							print('Upload exception: {}'.format(e))

				session.quit()


if __name__ == '__main__':

	parser = OptionParser()
	parser.add_option("--ip", dest="ip", default="",
					  help="ftp server (ecm) ip address to connect to")
	parser.add_option("--user", dest="user", default="ecm",
					  help="username (default = ecm)")
	parser.add_option("--pwd", dest="pwd", default="ecm", help="password (default = ecm)")
	parser.add_option("--cust_fw_path", dest="cust_fw_path", default="/home/ecm/Projects/rome/custom_firmware", help="ECM custom firmware path (default = /home/ecm/Projects/rome/custom_firmware")
	parser.add_option("--test_path", dest="test_path", default="", help="path to the Migration test script")
	parser.epilog ='Example: python3 ECMTestFirmwareDeploy.py --ip 172.19.9.23 --user ecm --pass ecm'
	(options, args) = parser.parse_args()

	if options.ip == "":
		print('ECM server IP not included (--ip), skipping update to custom_firmware')


	if options.test_path == "":
		print('Migration test_path not included (--test_path) - skipping Migration test file update')

	tool = ECMTestFirmwareTool(host=options.ip, username=options.user, password=options.pwd, test_path = options.test_path, cust_fw_path=options.cust_fw_path)
	if tool:
		tool.refresh()

	exit()