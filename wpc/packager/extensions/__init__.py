"""
ECM Merged 2/6/2018
service_manager/services/httpserver/__init__.py

Tornado based http server
"""

__copyright__ = """
Copyright (c) 2009-2013 CradlePoint, Inc. <www.cradlepoint.com>.
All rights reserved.

This file contains confidential information of CradlePoint, Inc. and your
use of this file is subject to the CradlePoint Software License Agreement
distributed with this file. Unauthorized reproduction or distribution of
this file is subject to civil and criminal penalties. """

import os
import services
import ssl
import base64
import hashlib
import services.bouncemgr
import threading
from cp import xtables
from wpc_config_store import WpcConfigStore  # ECM
from services import localnet
from services.utils import netfilter2 as nf
from services.httpserver.cpweb import CPStaticFileHandler
from services.httpserver.control import HTTPServerControl

from tornado import web
from tornado import ioloop
from tornado import httpserver


class HTTPService(services.Service):
	"""Web server / Gateway interface into config store"""

	name = 'httpserver'

	__startup__ = 80
	__shutdown__ = 100

	CUSTOM_SSL_CRT = '/tmp/admin_https.crt'
	CUSTOM_SSL_KEY = '/tmp/admin_https.key'

	def APIWorker(self):
		while True:
			self.apiqueue.get()()
			self.apiqueue.task_done()


	def _updateAuthUsers(self, path, users):
		""" Update local user list with all group==admin users """

		passwd = services.get('passwd')

		self.users.clear()
		for x in filter(lambda x: x['group'] == 'admin', users):
			self.users[x['username']] = {
				"password": passwd.pw_get(x['username']),
				"fail_log": passwd.faillog[x['username']]
			}

	def _updateCookie(self, path, user):
		""" If the user has just updated their password via the UI they will
			lose connectivity on the next request, update their cookie in-flight
		"""
		handler = self.apiworker.active_handler

		if handler and handler.current_user:
			if user['username'] == handler.current_user.decode():
				# we need to immediately update the local cache so we get the
				# correct password when the callback to cookie_secret is called
				self._updateAuthUsers(None, self.cStore.get('config.system.users', eventing=False))
				handler.set_secure_cookie(handler.settings['auth_cookie'], user['username'], version=1, expires_days=None)

	def _updateCipherList(self, path, cipher_list):
		self.ssl_options['ciphers'] = cipher_list
		self.servers['mgmtServerSSL']['ssl_options'] = self.ssl_options
		self.restartHTTPThread()

	def __init__(self, cStore, **kwargs):
		import sys
		import queue

		from . import cs_handler, cfgdiff_handler, bounce_handler, login_handler
		from . import admin_handler, fw_handler, plt_handler 
		from . import webfilter_handler, shared_handler, logfile_handler, wanprofile_handler, microstatus_handler

		super().__init__(cStore, **kwargs)

		self.http_thread = None
		self.servers = {}
		self.users = {}
		if not self.wpc:  # ECM
			self.cStore.on(self._updateAuthUsers, 'put', 'config.system.users')
			self._updateAuthUsers(None, self.cStore.get('config.system.users', eventing=False))
			self.cookie_secret_base = hashlib.sha256(os.urandom(16)).hexdigest()

		# Dynamic server control
		self.control = HTTPServerControl(self.cStore, self.logger, self)

		# generate a worker thread for slow API requests
		# if this service ever gets stopped we should kill this thread
		self.apiqueue = queue.Queue()
		self.apiworker = threading.Thread(None, self.APIWorker, "HTTPAPIWorker")
		self.apiworker.daemon = True
		self.apiworker.start()

		# if a password is updated via the REST interface we potentially need
		# to update the cookie signature as well, do it in the same context but
		# ensure our priority is lower than the password class' priority
		self.apiworker.active_handler = None
		self.cStore.on(self._updateCookie, 'put', 'config.system.users.*', msdelay=0, priority=51)

		base_dir = os.path.dirname(os.path.abspath(__file__))

		# WPC: SM_RUN_PORT must be in the environment in wpc mode 
		if self.wpc:
			mgmtPort = int(os.environ['SM_RUN_PORT'])
			mgmtPortSsl = (int(os.environ['SM_RUN_PORT']) + 1)
			ui_dir = os.path.join(base_dir, '../../../ui')

		self.cStore.on(self._updateCipherList, 'put', 'config.system.cipher_list')

		#https://wiki.mozilla.org/Security/Server_Side_TLS  (Modern compatibility)
		cipher_list = self.cStore.get('config.system.cipher_list', eventing=False)

		self.ssl_options = {
				"certfile": os.path.join(base_dir, "ssl.crt"),
				"keyfile": os.path.join(base_dir, "ssl.key"),
				"ssl_version": ssl.PROTOCOL_SSLv23,
				"ciphers": cipher_list,
				"options": ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_CIPHER_SERVER_PREFERENCE
		}

		minimum_tls_version = self.cStore.get('config.system.minimum_tls_version', eventing=False)
		pci_dss = self.cStore.get('config.system.pci_dss', eventing=False)

		if minimum_tls_version == 'tlsv1.1':
			self.ssl_options['options'] |= ssl.OP_NO_TLSv1
		elif minimum_tls_version == 'tlsv1.2':
			self.ssl_options['options'] |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

		# Only allow TLSv1.1 or TLSv1.2 if PCI-DSS is enabled
		if pci_dss and minimum_tls_version == 'tlsv1.0':
			self.ssl_options['options'] |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

		# Look for custom cert for SSL
		self.cStore.on(self.certUpdate, 'put', 'config.system.admin.secure_cert_uuid')
		self.certUpdate(None, self.cStore.get('config.system.admin.secure_cert_uuid'))

		# Setup tornado applications ..
		version = self.cStore.get('status.fw_info.build_version', eventing=False)

		mgmt_routes = [
				("/api/certexportca(.*)", services.certmgmt.CertExportCAHandler, {"service": self}),
				("/api/certimportca(.*)", services.certmgmt.CertImportCAHandler, {"service": self}),
				("/api/certcsr(.*)", services.certmgmt.CertCSRHandler, {"service": self}),
				("/api/certexport(.*)", services.certmgmt.CertExportHandler, {"service": self}),
				("/api/certimport(.*)", services.certmgmt.CertImportHandler, {"service": self}),
				("/api/tcpdump/(.*).pcap", services.tcpdump.TcpdumpHandler, {"service": self, "cStore": self.cStore}), # ECM
				("/api/dtd(.*)", cs_handler.ConfigStoreDTDHandler, {"service": self, "cStore": self.cStore}),  # ECM
				("/api/diff(.*)", cfgdiff_handler.CfgDiffHandler, {"service": self}),
				("/api/default", cs_handler.ConfigStoreDefHandler, {"service": self, "cStore": self.cStore}),  # ECM
				("/api/fm(.*)", cs_handler.FileManagerHandler, {"service": self, "cStore": self.cStore}),  # ECM
				("/api/wanprofile(.*)", wanprofile_handler.WanProfileHandler, {"service": self}),
				("/api/microstatus(.*)", microstatus_handler.MicroStatusHandler, {"service": self}),
				("/api(.*)", cs_handler.ConfigStoreHandler, {"service": self, "cStore": self.cStore}),  # ECM

				("/admin/(.*)", admin_handler.AdminHandler, {
					"path": ui_dir+"/admin",
					"template_vars": dict(),
					"service": self
				}),
				("/admin", web.RedirectHandler, {"url": "/admin/"}),

				("/resources/(.*)", shared_handler.SharedHandler, {"path": ui_dir+"/resources", "service": self}),

				("/login/(.*)", login_handler.LoginHandler, {
					"path": ui_dir+"/login",
					"template_vars": dict(),
					"service": self
				}),
				("/login", web.RedirectHandler, {"url": "/login/"}),

				("/config_save(.*)", cs_handler.ConfigSaveHandler, {"service": self, "cStore": self.cStore}),  # ECM
				("/log_save", logfile_handler.LogSaveHandler, {"service": self, "cStore": self.cStore}),  # ECM
				("/log_save_safe", logfile_handler.LogSaveHandler, {"service": self, "cStore": self.cStore, "cStoreEvent": False}),  # ECM

				("/routerlog.txt", logfile_handler.LogFileHandler, {"service": self}),
				("/qa_routerlog.txt", logfile_handler.LogFileHandlerDigest, {"service": self}),

				("/fw_upgrade(.*)", fw_handler.RouterFWHandler, {"service": self}),
				("/modem_fw_upgrade(.*)", fw_handler.ModemFWHandler, {"service": self}),

				(".*", web.RedirectHandler, {"url": "/admin/"})
		]

		mgmt_kwargs = {
				'login_url': "/login/",
				'users': self.users,
				'passwd': services.get('passwd'),
				'auth_cookie': 'user',
				'auth_realm': self.cStore.get('status.product_info.product_name', eventing=False),
				'cookie_secret': self.cookie_secret,
				# 'xsrf_cookies': True, # Required cookie token is not available in ECM
				'logger': self.logger,
				'version': version
		}

		mgmt_host_port_pair = ((mgmtPort, '0.0.0.0'), (mgmtPort, '::'))
		mgmt_host_port_pair_ssl = ((mgmtPortSsl, '0.0.0.0'), (mgmtPortSsl, '::'))
		#backup mgmtServer/mgmtServerSSL
		self.mgmtServer = {
				'routes': mgmt_routes,
				'host_port_pair': mgmt_host_port_pair,
				'kwargs': mgmt_kwargs
		}

		self.mgmtServerSSL = {
				'routes': mgmt_routes,
				'host_port_pair': mgmt_host_port_pair_ssl,
				'kwargs': mgmt_kwargs
		}

		self.createServer('mgmtServer', mgmt_host_port_pair, mgmt_routes, mgmt_kwargs, max_buffer_size=10*1024*1024)
		self.createServer('mgmtServerSSL', mgmt_host_port_pair_ssl, mgmt_routes, mgmt_kwargs, ssl_options=self.ssl_options)

		# ECM - Servers Not Needed
		# bounce_host_port_pair = ((services.bouncemgr.proxy_port, localnet.internal['bounce']), )
		# self.createServer('bounceServer', bounce_host_port_pair, [
		# 	("/resources/(.*)", shared_handler.SharedHandler, {"path": ui_dir+'/resources', "service": self}),
		# 	("/(.*)", bounce_handler.BounceHandler, {
		# 		"path": ui_dir+'/bounce',
		# 		'template_vars': dict(),
		# 		"service": self
		# 	})
		# ])

		# affinity_bounce_host_port_pair = ((services.bouncemgr.affinity_proxy_port, localnet.internal['affinity']), )
		# self.createServer('affinityBounceServer', affinity_bounce_host_port_pair, [
		# 	("/resources/(.*)", shared_handler.SharedHandler, {"path": ui_dir+'/resources', "service": self}),
		# 	("/(.*)", bounce_handler.AffinityBounceHandler, {
		# 		"path": ui_dir+'/bounce',
		# 		'template_vars': dict(),
		# 		"service": self
		# 	})
		# ])

		# webfilter_host_port_pair = ((30000, '0.0.0.0'), (30000, '::') )
		# self.createServer('webFilterServer', webfilter_host_port_pair, [
		# 	("/resources/(.*)", shared_handler.SharedHandler, {"path": ui_dir+'/resources', "service": self}),
		# 	("/(.*)", webfilter_handler.WebFilterHandler, {
		# 		"path": ui_dir+'/webfilter',
		# 		'template_vars': dict(),
		# 		"service": self
		# 	})
		# ])

		self.restartHTTPThread()


	def cookie_secret(self, key, b64username, *args):
		""" Change our cookie secret based on password for this user, so that
		password changes will invalidate the previous cookie secret. """
		username = base64.b64decode(b64username).decode()
		userent = self.users.get(username)
		if not userent:
			return self.cookie_secret_base
		else:
			return self.cookie_secret_base + \
			       hashlib.sha1(userent.get('password').encode()).hexdigest()

	def createServer(self, name, host_port_pair, routes, kwargs=None, ssl_options=None, max_buffer_size=None): # ECM
		server = {}

		if not isinstance(host_port_pair, tuple):
			raise Exception('missing host/port pair')

		server['routes'] = routes
		server['ipv4_port'] = host_port_pair[0][0]
		server['ipv4_host'] = host_port_pair[0][1]

		if len(host_port_pair) == 2:
			server['ipv6_port'] = host_port_pair[1][0]
			server['ipv6_host'] = host_port_pair[1][1]

		server['kwargs'] = kwargs if kwargs else {}
		server['ssl_options'] = ssl_options
		server['max_buffer_size'] = max_buffer_size # ECM

		self.servers[name] = server

	def getRoutes(self, name=None):
		routes = []
		server = self.servers.get(name)
		if server and server.get('routes'):
			routes = server.get('routes')

		if not server:
			for _, value in self.servers.items():
				routes.append(value.get('routes'))

		return routes

	def create_backup_routes(self, current_routes):
		backup_routes = []
		for curr_route in current_routes:
			curr_rt_name, curr_rt_handler, curr_rt_dict = curr_route
			backup_rt_name = curr_rt_name
			backup_rt_path = curr_rt_dict.get("path")
			backup_routes.append((backup_rt_name, backup_rt_path))
		return backup_routes

	def updateRoutes(self, name=None, routes=None):
		if name is None or routes is None:
			self.logger.debug('updateRoutes incorrect parameters')
			return False

		if name not in ['bounceServer', 'affinityBounceServer',
				'hotspotBounceServer', 'hotspotServer',
				'hotspotProxyServer']:
			self.logger.error("server '%s' not an updatable server", name)
			return False

		server = self.servers.get(name)
		if not server:
			self.logger.debug('Unknown server %s', name)
			return False

		if server.get('backup_routes'):
			self.logger.debug('Server %s already modified')
			return False

		current_routes = server.get('routes')
		server['backup_routes'] = self.create_backup_routes(current_routes)

		for route in routes:
			if len(route) != 2:
				self.logger.error("Malformed route detected '%s'", route)
				continue

			rt_name, rt_path = route

			for curr_route in current_routes:
				curr_rt_name, curr_rt_handler, curr_rt_dict = curr_route

				if rt_name == curr_rt_name:
					curr_rt_dict["path"] = rt_path

		return True

	def restore_backup_routes(self, current_routes, backup_routes):
		for curr_rt in current_routes:
			curr_rt_name, curr_rt_handler, curr_rt_dict = curr_rt
			for backup_rt in backup_routes:
				backup_rt_name, backup_rt_path = backup_rt
				if curr_rt_name == backup_rt_name:
					curr_rt_dict["path"] = backup_rt_path

	def restoreRoutes(self, name=None):
		if name is None:
			self.logger.debug('restoreRoutes incorrect parameters')
			return False

		server = self.servers.get(name)
		if not server:
			self.logger.debug('Unknown server %s', name)
			return False

		server = self.servers.get(name)
		if not server.get('backup_routes'):
			self.logger.debug('Server %s has not been modified')
			return False

		self.restore_backup_routes(server['routes'], server['backup_routes'])
		del server['backup_routes']

		return True

	def updateServers(self):
		for _, value in self.servers.items():
			routes = value.get('routes')
			kwargs = value.get('kwargs')
			server = value.get('server')
			options = value.get('ssl_options')
			max_buffer_size = value.get('max_buffer_size') # ECM

			no_keep_alive = True if kwargs.get('no_keep_alive') else False

			# self.logger.debug('routes = %s kwargs %s', routes, kwargs)

			application = web.Application(routes, **kwargs)

			if server:
				server.stop()
				del value['server']

			server = httpserver.HTTPServer(application, no_keep_alive=no_keep_alive, ssl_options=options, max_buffer_size=max_buffer_size) # ECM

			server.listen(value.get('ipv4_port'), value.get('ipv4_host'))
			if value.get('ipv6_port'):
				server.listen(value.get('ipv6_port'), value.get('ipv6_host'))

			value['application'] = application
			value['server'] = server

	def restartHTTPThread(self):
		if self.http_thread:
			ioloop.IOLoop.current().stop()
			self.http_thread.join(timeout=1)
			self.http_thread = None

		self.updateServers()

		self.http_thread = threading.Thread(None, ioloop.IOLoop.current().start, "HTTPThread")
		self.http_thread.daemon = True
		self.http_thread.start()

	def initRemAccessRules(self, xtable):
		with nf.getChain('mangle', 'PREROUTING_NEW', xtable) as mangle_preroute:
			mangle_preroute.addRule(nf.NFRule(
				triggers=(RemoteAdminTrigger, RemoteAdminPortTrigger, RemoteAdminNotSecureOnlyTrigger),
				protocol='tcp',
				target=nf.MarkTarget('for_router', 1)
			))
			mangle_preroute.addRule(nf.NFRule(
				triggers=(RemoteAdminTrigger, RemoteAdminSecurePortTrigger),
				protocol='tcp',
				target=nf.MarkTarget('for_router', 1)
			))

		with nf.getChain('nat', 'WAN_SERVERS', xtable) as wanNat:
			wanNat.addRule(nf.RedirectRule(
				triggers=(RemoteAdminTrigger, RemoteAdminPortTrigger, RemoteAdminNotSecureOnlyTrigger),
				to=self.mgmtPort,
				protocol='tcp'
			))
			wanNat.addRule(nf.RedirectRule(
				triggers=(RemoteAdminTrigger, RemoteAdminSecurePortTrigger),
				to=self.mgmtPortSSL,
				protocol='tcp'
			))

	def initLocalAccessRules(self, xtable):
		inetsuffix = '6' if xtable == 'ip6' else ''

		with nf.getChain('mangle', 'PREROUTING_NEW', xtable) as mangle_preroute:
			mangle_preroute.addRule(nf.NFRule(
				matches=nf.SetMatch('src,src', 'lan_admin%s' % inetsuffix),
				triggers=SecurePortTrigger,
				protocol='tcp',
				target=nf.MarkTarget('for_router', 1)
			))
			mangle_preroute.addRule(nf.NFRule(
				matches=nf.SetMatch('src,src', 'lan_admin%s' % inetsuffix),
				triggers=NotSecureOnlyTrigger,
				dport=self.mgmtPort,
				protocol='tcp',
				target=nf.MarkTarget('for_router', 1)
			))

		with nf.getChain('nat', 'LAN_SERVERS', xtable) as lanNat:
			lanNat.addRule(nf.RedirectRule(
				matches=nf.SetMatch('src,src', 'lan_admin%s' % inetsuffix),
				triggers=SecurePortTrigger,
				to=self.mgmtPortSSL,
				protocol='tcp'
			))

	def onStart(self):
		""" Open the firewall a bit. """

		for inet in ('ip', 'ip6'):
			self.initRemAccessRules(inet)
			self.initLocalAccessRules(inet)

		# This shouldn't be needed, but too many things* gratuitously ACCEPT, plus we
		# should block before USER_IP_FILTER_IN because 'secure_only' is a specific user override.
		# This is added in PRE_USER_IN to ensure after any bad packets but before the user chain.
		nf.getChain('filter', 'PRE_USER_IN').addRule(nf.DropRule(matches=(nf.SetMatch('dst', 'lan_router'),
		                                            xtables.Match('tcp', dport=self.mgmtPort)),
		                                triggers=SecureOnlyTrigger, protocol='tcp'))
		# * things: ipsec, gre tunnels, static routes with net allow, maybe more?

	def certUpdate(self, path, cert_uuid):
		if cert_uuid:
			from services import certmgmt
			cert, key = certmgmt.findCert(cert_uuid)
			try:
				with open(self.CUSTOM_SSL_CRT, 'wb') as f:
					os.chmod(self.CUSTOM_SSL_CRT, 0o600)
					f.write(cert)
				with open(self.CUSTOM_SSL_KEY, 'wb') as f:
					os.chmod(self.CUSTOM_SSL_KEY, 0o600)
					f.write(key)
				self.ssl_options["certfile"] = self.CUSTOM_SSL_CRT
				self.ssl_options["keyfile"] = self.CUSTOM_SSL_KEY
			except AttributeError:
				self.logger.error("SSL certificate configured but not found.")
		else:
			base_dir = os.path.dirname(os.path.abspath(__file__))
			self.ssl_options["certfile"] = os.path.join(base_dir, "ssl.crt")
			self.ssl_options["keyfile"] = os.path.join(base_dir, "ssl.key")
			# ensure we cleanup custom certs
			try:
				os.remove(self.CUSTOM_SSL_CRT)
			except FileNotFoundError:
				pass
			try:
				os.remove(self.CUSTOM_SSL_KEY)
			except FileNotFoundError:
				pass

services.register(HTTPService)

class RemoteAdminTrigger(nf.BoolTrigger):
	_shared_state = {}
	path = 'config.firewall.remote_admin.enabled'

class RemoteAdminNotSecureOnlyTrigger(nf.BoolTrigger):
	_shared_state = {}
	path = 'config.firewall.remote_admin.secure_only'

	def update(self, rule, path, value):
		return not value

class RemoteAdminPortTrigger(nf.PortTrigger):
	_shared_state = {}
	path = 'config.firewall.remote_admin.port'
	protocol = 'tcp'
	direction = 'dst'

class RemoteAdminSecurePortTrigger(RemoteAdminPortTrigger):
	_shared_state = {}
	path = 'config.firewall.remote_admin.secure_port'

class SecurePortTrigger(nf.PortTrigger):
	_shared_state = {}
	path = 'config.system.admin.secure_port'
	protocol = 'tcp'
	direction = 'dst'

class SecureOnlyTrigger(nf.BoolTrigger):
	_shared_state = {}
	path = 'config.system.admin.secure_only'

class NotSecureOnlyTrigger(nf.BoolTrigger):
	_shared_state = {}
	path = 'config.system.admin.secure_only'

	def update(self, rule, path, value):
		return not value
