"""
ECM Merged 2/6/2018
service_manager/services/httpserver/cpweb.py

Extentions to the tornado web module to provide cradlepoint utility.
"""

__copyright__ = """
Copyright © 2009 CradlePoint, Inc. <www.cradlepoint.com>.
All rights reserved.

This file contains confidential information of CradlePoint, Inc. and your
use of this file is subject to the CradlePoint Software License Agreement
distributed with this file. Unauthorized reproduction or distribution of
this file is subject to civil and criminal penalties. """

import os
import io
import logging
import config_store
import services
import tornado
from tornado import web
import ipaddress
import cp
import cp.arp
import cp.xtables
from services.alerts import addAlert, AccountLocked
from cp import uptime


import mimetypes
mimetypes.add_type('text/css', '.cgz')
mimetypes.add_type('application/javascript', '.jgz')

_debug = False

def dbg_print(*args, **kwargs):
	if _debug:
		print ("DBG(%s):" % __name__, *args, **kwargs)

class CPRequestHandler(tornado.web.RequestHandler):
	""" Provide some cradlepoint functionality to base request handler class """
	ccheaders = {
		'Cache-Control': 'no-store, no-cache, private, max-age=0',
		'Expires': '-1',
		'Pragma': 'no-cache'
	}

	def __init__(self, *args, service=None, **kwargs):
		""" Attach service instance to this request """
		self.service = service
		return super().__init__(*args, **kwargs)

	@property
	def logger(self):
		return self.settings.get('logger', logging)

	@staticmethod
	def extjsFilter(input, success=True):
		""" Format output data structure into format our web UI prefers """
		return { 'success': success, 'data': input }


	def outputFilter(self, input, success=True):
		""" Produce correctly formatted json output for REST clients """
		jsonEncoder = config_store.ConfigJsonEncoder()
		return jsonEncoder.encode(self.extjsFilter(input, success))


	def get_current_user(self):
		return self.get_secure_cookie(self.settings.get('auth_cookie', 'user'))

	def get_session_timeout(self):
		user = self.get_secure_cookie(self.settings.get('auth_cookie', 'user')).decode()
		if user not in self.settings['users']:
			return 0
		elif 'session_timeout' not in self.settings['users'][user]:
			return 0
		else:
			return self.settings['users'][user].get('session_timeout')

	def get_idle_timeout(self):
		user = self.get_secure_cookie(self.settings.get('auth_cookie', 'user')).decode()
		if user not in self.settings['users']:
			return 0
		elif 'idle_timeout' not in self.settings['users'][user]:
			return 0
		else:
			return self.settings['users'][user].get('idle_timeout')

	def async_complete(self, data=b''):
		""" This function wraps the ioloop callback system that allows us to
		safely write data to our network socket in the same thread as IOLoop.
		If you are doing asyncronous work in a thread besides the main IOLoop
		thread then you *MUST* use this routine to avoid race conditions and
		occasional deadlocks on keep-alive connections. """
		ioloop = tornado.ioloop.IOLoop.instance()
		ioloop.add_callback(lambda: self.on_async_complete(data))


	def on_async_complete(self, data):
		""" Called via ioloop to finish async threaded requests """
		self.write(data)
		self.finish()

	def get_template_namespace(self):
		"""override to pull remove current user from the namespace dict() as
		it causes trouble as then we are trying to request secure cookies
		at the template stage which is not what we want. """
		namespace = dict(
			handler=self,
			request=self.request,
			static_url=self.static_url,
			xsrf_form_html=self.xsrf_form_html,
			reverse_url=self.reverse_url
		)
		namespace.update(self.ui)
		return namespace

	def error(self, reason):
		self.write(self.outputFilter({
			"exception": "server",
			"reason": reason
		}, False))
		return self.finish()

	def success(self, **kwargs):
		self.write(self.outputFilter(kwargs if kwargs else 'valid', True))
		return self.finish()

	def check_xsrf_cookie(self):
		if self.cookies:
			super(CPRequestHandler, self).check_xsrf_cookie()


def restmethod(method):
	""" decorator to make http method callbacks restish """

	def restish(instance, request):

		base = tuple(filter(lambda x: len(x) > 0, request.split('/')))
		query = { key: instance.get_arguments(key, strip=False) for key in instance.request.arguments.keys() }

		return method(instance, base, **query)

	return restish


def authenticate(session=True, auth=False):
	""" decorator to require session and/or digest based auth.
	If no authentication can be made the user is redirected
	to the login page for session only. """

	def wrapper(method):
		""" Our decorator has to be executed so another wrapper layer for a 2nd
		closure is required to tie in the session and digest attributes """

		def check_auth(instance, *args,  **kwargs):
			# [ECM] Disable authentication
			return method(instance, *args, **kwargs)

		return check_auth

	return wrapper


class CPStaticFileHandler(tornado.web.StaticFileHandler, CPRequestHandler):
	""" Support precompressed css and js also support directory indexing. """

	enable_dirindex = False
	version_tag = [] # use class var for faster access to the version tag
	x_frame_options = "DENY" # prevent "click-jacking"

	def dirindex(self, request):
		"""Read directory contents and return HTML index of contents"""

		sio = io.StringIO()

		sio.write("<html><head><title>{0}</title></head><body><h1>{0}</h1><ul>\n".format(
			"Directory index for: %s" % self.request.uri))

		fullpath = os.path.join(self.root, request)
		fmt = '<li><a href="{0}">{0}</a></li>\n'
		sio.write(fmt.format('.')) # current dir (reload)
		sio.write(fmt.format('..')) # parent dir
		for x in os.listdir(fullpath):
			sio.write(fmt.format(x))

		return sio.getvalue()


	def get(self, request, include_body=True):
		"""Handle static file requests, with auth.  Sets correct header for
		precompressed (gzip) css and javascript files; *.cgz and *.jgz respectively"""

		if self.x_frame_options:
			self.set_header("X-Frame-Options", self.x_frame_options)

		if not request or len(request) == 0:
			try: return self.get('index.html', include_body=include_body)
			except: self.logger.error('failed to get index', exc_info=True)

		# handle precompressed content
		ext = os.path.splitext(request)[1]
		if ext in ('.cgz', '.jgz'):
			self.set_header('Content-Encoding', 'gzip')

		if self.enable_dirindex and os.path.isdir(os.path.join(self.root, request)) and len(request) > 0:
			# add trailing slash (if needed) before processing as a dir so relative links work
			if request[-1] != '/':
				return self.redirect(self.request.uri + '/')
			if include_body:
				self.write(self.dirindex(request))
			return
		else:
			return super().get(request, include_body=include_body)


	def v_cache(self, url):
		""" Add a version argument to the url to force aggressive caching.
		This improves performance and actually helps prevent cache coheriancy issues
		during a firmware upgrade because the urls are always bound to the fw version. """

		if not self.version_tag:
			# first request must lazy init the version tag class var
			fw_info = config_store.ConfigStore().get('status.fw_info')
			pname = config_store.ConfigStore().get('status.product_info.product_name').lower()
			self.version_tag.append('%d.%d.%d-%s-%s' % (fw_info['major_version'], fw_info['minor_version'],
			                                         fw_info['patch_version'], fw_info['build_version'], pname))

		return "%s?v=%s" % (url, self.version_tag[0])


class CPTemplateFileHandler(CPStaticFileHandler):
	""" Renders files matching the template file extention or just
	delivers static files.  Think Apache/PHP but with python.
	We use tornado's template system which expects the variables
	of interest to be passed at render time, so implementors of
	this class need to provide the arguments fed into template
	files.  Future versions might support var sets for different
	pages.

	To support common file types the required filename convention
	is FILENAME.{template_ext}.CONTENT_EXT, for example.
	A request to /foo.html will look for /foo.tpl.html and set
	the content type to text/html.  If a template file is not
	found we simply fall through to the static file handler. """

	template_ext = 'tpl'

	# this is a class variable so it can be accessed in all template handlers
	if cp.platform == 'router':
		admin_ip_set = cp.xtables.IPSet('admin_ips', 'hash:ip')
		admin_ip_set6 = cp.xtables.IPSet('admin_ips6', 'hash:ip', 'family', 'inet6')
	else:
		admin_ip_set = None
		admin_ip_set6 = None

	def __init__(self, *args, template_vars=None, **kwargs):
		""" Store the variables passed to tornado render
		function for any future requests. """

		self.template_vars = template_vars.copy() if template_vars is not None else {}
		self.template_vars.update({
			"has_admin_access": self.has_admin_access,
			"server_host": self.server_host,
			"v_cache": self.v_cache
		})
		super().__init__(*args, **kwargs)

	@staticmethod
	def admin_ip_op(op, value):
		""" execute the op(value) for the admin_ip_set which is called from the
		login page when we are logging out or session times out """

		ipsets = {4: CPTemplateFileHandler.admin_ip_set, 6: CPTemplateFileHandler.admin_ip_set6}

		try:
			ip = ipaddress.ip_address(value)
			m = getattr(ipsets.get(ip.version), op)
			if callable(m):
				m(value)
		except:
			pass

	@staticmethod
	def cs_getter(accessor, default=None, query=None):
		""" Allow safe template access to ConfigStore without raising an exception.
		Return the result or in case of error return the optional default
		string.  Example usage: cs_getter('foo.bar.bla', 'no value found') """

		# for performance might need to not trigger get() event
		# or to cache the result
		# (based on recent within some uptime() ticks?)
		try:
			data = config_store.ConfigStore().get(accessor, query=query)
		except:
			data = None

		return data if data is not None else default


	def has_modem(self):
		""" Return true if WAN modem devices are available """

		wanmgr = services.get('wm2').manager
		if not wanmgr:
			return False

		return not not [ x for x in wanmgr.findDevices() if x.type not in {'ethernet', 'wwan'} ]


	def get_modem_list(self):
		""" Return a list of WAN modem devices. """

		wanmgr = services.get('wm2').manager
		modems = [ x for x in wanmgr.findDevices() if x.type not in {'ethernet', 'wwan'} ]

		ml = []
		for modem in modems:
			ml.append({'type' : modem.type, 'manufacturer' : modem.manufacturer,
				'model' : modem.model, 'rssi' : modem.diag.get('DBM', '0'),
				'signal_strength' :  modem.signal_strength, 'service_type' : modem.service_type,
				'status' : modem.connection_state})

		return ml


	def get_mac(self, ipaddr):
		""" Return the mac address of the requested ipaddr."""
		return tuple(filter(lambda x: x['ip_address'] == ipaddr, cp.arp.dump()))[0]['hwaddr']


	def get_defmac(self):
		""" Return the router's default mac address."""
		return services.get('portmgr').default_mac


	def get(self, request, *args, include_body=True, **kwargs):
		""" Look for template files and render if found """

		x = os.path.splitext(request)
		tpl_file = '%s.%s%s' % (x[0], self.template_ext, x[1])

		# Shamelessly copied from tornado/web.py for security of template files
		abspath = os.path.abspath(os.path.join(self.root, tpl_file))
		if not abspath.startswith(self.root):
			raise tornado.web.HTTPError(403, "%s is not in root static directory", request)

		if os.path.isfile(abspath):
			mime = mimetypes.guess_type(abspath)[0]
			if mime:
				self.set_header('Content-type', mime)

			if include_body:
				for h, v in self.ccheaders.items():
					self.set_header(h, v)
				self.render(
					abspath,
					cs_getter=self.cs_getter,
					has_modem=self.has_modem,
					get_modem_list=self.get_modem_list,
					get_mac=self.get_mac,
					get_defmac=self.get_defmac,
					handler=self,
					**self.template_vars)
			return
		else:
			return super().get(request, *args, include_body=include_body, **kwargs)


	def server_host(self):
		""" Return the server ip address or hostname.  The value is tuned to
		match the network of the client. """

		lm = services.get('lan').manager

		for x in lm.findNetworks():
			if ipaddress.ip_address(self.request.remote_ip) in ipaddress.ip_network('{}/{}'.format(x.ip_address,x.netmask)):
				return x.ip_address

		wan_ip = config_store.ConfigStore().get('status.wan.ipinfo.ip_address')
		if wan_ip:
			return wan_ip

		self.logger.warning("Could not find matching server IP for web redirect.")

		return lm.findNetworks()[0].ip_address # better than nothing?


	def has_admin_access(self):
		""" Test to see if this client can actually access the admin pages. """

		lanInfo = config_store.ConfigStore().get('config.lan', eventing=False)

		for lan in lanInfo:
			if lan['admin_access'] and ipaddress.ip_address(self.request.remote_ip) in ipaddress.ip_network('{}/{}'.format(lan['ip_address'],lan['netmask'])):
				return True

		return False


	def addr_is_lan(self):
		"""Test the request address for LAN and guest LAN association. """

		lanmgr = services.get('lan').manager
		if not lanmgr:
			return False

		ipver = ipaddress.ip_address(self.request.remote_ip).version
		for x in lanmgr.findNetworks():
			for ip in x.ipaddrs:
				ipnet = ipaddress.ip_network(ip)
				if ipver == ipnet.version:
					if ipnet.compare_networks(ipaddress.ip_network('{}/{}'.format(self.request.remote_ip, ipnet.prefixlen), strict=False)) == 0:
						return True

		return False
