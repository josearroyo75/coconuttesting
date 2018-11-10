from cloudfiles.errors import NoSuchObject




import os
import requests
import cloudfiles
from dateutil import parser as du_parser
import shutil
import hashlib
import json
import argparse
import glob
import subprocess


# Refresh firmware error representation
class RefreshFirmwareException(Exception):
    pass


class RefreshFirmwareTool(object):
    def __init__(self, host, username='admin', password='admin',
                 base_path=None, product=None, version=None):
        self.base_path = base_path
        if self.base_path is None:
            self.base_path = os.environ.get('ROME_S3_CONFIG_PAGES_DIR',
                                            '/tmp/config_pages/')
        product = product or '**'
        version = version or '**'
        path = os.path.join(self.base_path, product, version, '**', 'html',
                            'rinfo.json')
        print(path)
        self.rinfo_files = glob.glob(path)
        print(self.rinfo_files)
        self.host = host
        self.session = requests.session()
        self.session.auth = (username, password)
        self.session.headers.update({'accept': 'application/json',
                                     'content-type': 'application/json',
                                     'host': 'wipipecentral.com'})

    def _http_get(self, path, params=None):
        url = '{0}{1}'.format(self.host, path)
        try:
            resp = self.session.get(url, verify=False, params=params)
            if resp.status_code != 200:
                raise RefreshFirmwareException(
                    'Got status code {} on {} during GET with params={}'.
                    format(resp.status_code, url, params))
            return resp.json()
        except requests.exceptions.ConnectionError as e:
            raise RefreshFirmwareException('Could not connect to {0}'.
                                           format(url))

    def _http_post(self, path, data):
        if not isinstance(data, str) and not isinstance(data, unicode):
            data = json.dumps(data)
        url = '{0}{1}'.format(self.host, path)
        resp = self.session.post(url, data=data)
        if resp.status_code not in (200, 201):
            raise Exception('Got status code {0} on {1} during POST'.
                            format(resp.status_code, url))
        return resp.json()

    def build_fw_paths(self, rinfo_path):
        fw_base = os.path.abspath(os.path.join(os.path.dirname(rinfo_path),
                                               '..'))
        print(fw_base)
        fw_path = glob.glob(os.path.join(fw_base, '*.bin'))[0]

        return fw_base, fw_path

    def firmware_exists(self, sha1_hash, product_id):
        params = {
            'hash': sha1_hash,
            'product': product_id
        }
        resp = self._http_get('/api/v1/firmwares/', params=params)

        if len(resp['data']) == 0:
            return False
        return resp['data'][0]


    def get_sha1_hash(self, path):
        sha1 = hashlib.sha1()
        with file(path, 'rb') as f:
            sha1.update(f.read())
            return sha1.hexdigest()



    def read_rinfo(self, path):
        with file(path, 'r') as f:
            return json.loads(f.read())

    def create_fw_record(self, dtd, sha1_hash, product, version, cloud_url,
                         timestamp):
        data = {
            'dtd': dtd,
            'hash': sha1_hash,
            'product': product,
            'version': version,
            'custom': '',
            'build_timestamp': timestamp,
            'release_date': timestamp,
            'url': cloud_url
        }

        response = self._http_post('/api/v1/firmwares/', json.dumps(data))
        return response

    def upload_dtd(self, dtd_path):
        with file(dtd_path, 'r') as f:
            data = f.read()
            f.close()
            data = json.loads(data)

        if 'config' in data:
            data = data['config']['nodes']
        resp = self._http_post('/api/v1/dtds/', json.dumps({'value': data}))
        return resp['data']['resource_uri']

    def find_product(self, product):
        if product == 'PEBBLES500':
            product = 'CBR400'
        if product == 'MBR1600':
            product = '2100'
        response = self._http_get('/api/v1/products/',
                                  params={'name': product})
        return response['data'][0]

    def refresh(self):
        for path in self.rinfo_files:
            parent_path = os.path.abspath(
                os.path.join(os.path.dirname(path), '..', '..', '..'))
            if not os.path.islink(parent_path):
                fw_base, fw_path = self.build_fw_paths(path)
                print('Searching in {}'.format(fw_base))
                print('Found FW Binary at {}'.format(fw_path))
                rinfo = self.read_rinfo(path)
                product = self.find_product(rinfo['product_name'])
                print("Product: {}".format(product))
                sha1_hash = self.get_sha1_hash(fw_path)
                if os.path.basename(fw_path) == 'fw.bin':
                    hash_path = os.path.join(
                        fw_base, '{}-{}.bin'.format(product['name'],
                                                    rinfo['build_time']))
                    shutil.move(fw_path, hash_path)
                    fw_path = hash_path

                exists = self.firmware_exists(sha1_hash, product['id'])
                if not exists:
                    print('Firmware at {0} does not exist in database. '
                          'Will upload binaries and create database records.'.
                          format(fw_base))
                    timestamp = du_parser.parse(rinfo['build_time']).isoformat()
                    print("Timestamp: {}".format(timestamp))
                    dtd = self.upload_dtd(
                        os.path.join(fw_base, 'service_manager',
                                     'config_dtd.jsonmin'))
                    print("DTD: {}".format(dtd))
                    version = rinfo['product_version']
                    print("Version: {}".format(version))
                    partial = os.path.relpath(fw_path, self.base_path)
                    url = '{0}/static/config_pages/{1}'.format(self.host,
                                                               partial)
                    print("URL: {}".format(url))
                    response = self.create_fw_record(
                        dtd, sha1_hash, product['resource_uri'], version, url,
                        timestamp)
                    print(response)
                    print('Firmware: {}'.
                          format(response['data']['resource_uri']))
                    print('Finding Similar Products')
                else:
                    print('Firmware already exists in database. Skipping.')


if __name__ == "__main__":
    default_host = "http://localhost:" + os.environ.get('PORT', '8008')

    parser = argparse.ArgumentParser()
    parser.add_argument('--host', help="The host to update [{}]".
                        format(default_host), default=default_host)
    parser.add_argument('--username', '-u',
                        help="The username to upload with [admin]",
                        default='ecm_admin')
    parser.add_argument('--password', '-p',
                        help="The password to upload with [admin]",
                        default='admin')
    parser.add_argument('--base_path', '-b',
                        help="The base path to scan for firmware from",
                        default=None)
    parser.add_argument('buildfile', help='Build info file')
    args = parser.parse_args()

    build = [x[:-1] for x in open(args.buildfile).readlines()]

    try:
        refresh = RefreshFirmwareTool(
            host=args.host, username=args.username, password=args.password,
            base_path=args.base_path, product=build[2], version=build[1])
        refresh.refresh()
    except RefreshFirmwareException as e:
        print 'ERROR: {0}'.format(e.message)
