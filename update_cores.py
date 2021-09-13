#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import collections
import logging
import logging.handlers
import configparser
import codecs
import sys
import os
import pathlib
import subprocess
import re
import json
import time
import xml.etree.ElementTree as Et
import html
import datetime
import urllib.parse
import pickle
import shutil
import email.utils as eut


# todo log MRA-alternatives in summary
# todo check handling of older MRA-Alternatives versions

class UpdateCoreError(RuntimeError):
    pass


class CacheHelper:
    """Cache in a work_path file of the data, with expiration time specified in the config"""

    def __init__(self, config, paths_helper):
        self.config = config
        self.paths_helper = paths_helper

    def read(self, filename):
        cache_file_path = self.paths_helper.get_work_filepath(filename, 'cache')
        try:
            cache_data = pickle.load(open(cache_file_path, 'rb'))
            cache_data_age = time.time() - cache_data['time']
            if cache_data_age > float(self.config['GENERAL']['REPOS_CACHE_LENGTH']):
                logging.debug('Cache data expired')
            else:
                logging.debug('Cache data is valid')
                return cache_data['data']
        except FileNotFoundError:
            return None

    def write(self, filename, data):
        cache_file_path = self.paths_helper.get_work_filepath(filename, 'cache')
        self.paths_helper.ensure_work_path_exists('cache')
        cache_data = {
            'time': time.time(),
            'data': data,
        }
        pickle.dump(cache_data, open(cache_file_path, 'wb'))


class GithubReposInfoHelper:

    def __init__(self, config, paths_helper, system_helper, cache_helper):
        self.config = config
        self.paths_helper = paths_helper
        self.system_helper = system_helper
        self.cache_helper = cache_helper
        self.mem_cache = {}

    def get_repo_info(self, repo_url):
        repo_url = self.get_repo_base_url(repo_url)
        logging.debug('Fetching repo info for URL: ' + repo_url)

        # try to fetch from cache
        owner = self.get_repo_owner(repo_url)
        if owner in self.mem_cache:
            logging.debug('Repo info in mem cache')
            all_repos = self.mem_cache[owner]
        else:
            cache_data_filename = 'repos_cache_' + owner
            all_repos = self.cache_helper.read(cache_data_filename)
            if all_repos is None:
                # fetch from Github API and write cache
                all_repos = self._fetch_repos_info(owner)
                self.cache_helper.write(cache_data_filename, all_repos)
                self.mem_cache[owner] = all_repos

        if repo_url in all_repos:
            return all_repos[repo_url]
        else:
            return None

    @staticmethod
    def get_download_url(remote_file):
        return remote_file + '?raw=true'

    @staticmethod
    def get_repo_base_url(repo_url):
        url_info = urllib.parse.urlparse(repo_url)
        url_info = url_info._replace(path='/'.join(url_info.path.split('/')[0:3]))
        return urllib.parse.urlunparse(url_info)

    @staticmethod
    def get_repo_owner(repo_url):
        url_info = urllib.parse.urlparse(repo_url)
        return str(url_info.path.split('/')[1])

    def get_repo_releases_url(self, repo_url, core_repo_info):
        base_url = self.get_repo_base_url(repo_url)
        url_info = urllib.parse.urlparse(repo_url)
        subpath = '/'.join(url_info.path.split('/')[4:])
        if subpath:
            return base_url + '/file-list/' + subpath + '/releases'
        else:
            return base_url + '/file-list/' + core_repo_info['default_branch'] + '/releases'

    def _fetch_repos_info(self, owner):
        repos_info_url = 'https://api.github.com/users/' + owner + '/repos'
        p = 1
        all_repos = {}
        while True:
            repos = self.system_helper.execute_curl(repos_info_url + '?per_page=100&page={}'.format(p),
                                                    append_body=True).body
            repos = json.loads(repos)
            if len(repos) == 0:
                break
            for repo in repos:
                svn_url = repo['svn_url']
                all_repos[svn_url] = self._filter_fields(repo, ['svn_url', 'full_name', 'name', 'updated_at',
                                                                'default_branch'])
            p = p + 1
        return all_repos

    def _filter_fields(self, repo, fields):
        return {k: v for k, v in filter(lambda f: f[0] in fields, repo.items())}


class SystemHelper:
    APPEND_BODY = "append_body"

    def __init__(self, config, paths_helper):
        self.config = config
        self.paths_helper = paths_helper
        self.curl_insecure = None

    def check_certificates(self):
        ret = self.execute_curl('https://github.com', raise_on_error=False).returncode
        if ret == 0:
            self.curl_insecure = False
            return
        elif ret == 60:
            if self.config.getboolean('GENERAL', 'ALLOW_INSECURE_SSL'):
                logging.info('Invalid CA Certificates. ALLOW_INSECURE_SSL active --> Using insecure curl')
                self.curl_insecure = True
            else:
                logging.warning(
                    "CA certificates need to be fixed for using SSL certificate verification. Please fix them i.e. "
                    "using security_fixes.sh")
                raise RuntimeError('Invalid SSL certificates and ALLOW_INSECURE_SSL option set to False')
        else:
            raise RuntimeError('No internet connection')

    @staticmethod
    def execute_subcommand(command):
        logging.debug('System command: %s' % command)
        completed_process = subprocess.run(command, shell=True, stdout=subprocess.PIPE)
        logging.debug('System command return code: %i' % completed_process.returncode)
        return completed_process

    def execute_curl(self, url, download_path=None, append_body=False, progress_bar=False, raise_on_error=True):

        params = ["--connect-timeout 15 --max-time 180 --retry 3 --retry-delay 5 -L"]
        if self.curl_insecure is True:
            params.append('--insecure')
        if progress_bar:
            params.append('--progress-bar')
        else:
            params.append('--silent')
        headers_file = self.paths_helper.get_work_filepath('temp_headers', 'temp')
        self.paths_helper.ensure_work_path_exists('temp')
        params.append("-D \"" + headers_file + "\"")
        delete_download_path = False
        if append_body is True:
            if download_path is None:
                download_path = self.paths_helper.get_work_filepath('temp_body', 'temp')
                delete_download_path = True
        if download_path is None:
            params.append('-I')  # headers only
        else:
            params.append("-o \"" + download_path.replace("\"", "\\\"") + "\"")
        params.append("\"" + url.replace("\"", "\\\"") + "\"")
        params = ' '.join(params)
        command = 'curl ' + params
        ex = self.execute_subcommand(command)
        ex.headers = self._parse_headers_file(headers_file)
        if append_body:
            with open(download_path, "r") as f:
                ex.body = f.read()
                f.close()
            if delete_download_path:
                os.unlink(download_path)
        else:
            ex.bodypath = download_path

        if len(ex.headers) > 0:
            ex.httpcode = int(re.search(r'(\d{3})', ex.headers[-1]['status']).group(0))
        else:
            ex.httpcode = None
        os.unlink(headers_file)
        if raise_on_error and ex.returncode != 0:
            if ex.returncode == 23:
                logging.critical('  DISK FULL!!!!!!!!!!!!!!!!!!!!')
            raise RuntimeError('  Error (' + str(ex.returncode) + ') in CURL request. URL: ' + url)
        return ex

    def get_files_in_zip(self, zipfile_path):
        params = []
        params.append("-Z1")
        params.append("\"" + zipfile_path.replace("\"", "\\\"") + "\"")
        params = ' '.join(params)
        command = 'unzip ' + params + " | grep -v '/$'"
        return self.execute_subcommand(command).stdout.decode('utf-8').strip(' \n')

    def execute_unzip(self, zipfile_path, destination_path):
        params = []
        params.append("-d \"" + destination_path.replace("\"", "\\\"") + "\"")
        params.append("\"" + zipfile_path.replace("\"", "\\\"") + "\"")
        params = ' '.join(params)
        command = 'unzip ' + params
        return self.execute_subcommand(command)

    @staticmethod
    def _parse_headers_file(headers_file):
        headers_list = []
        headers = collections.OrderedDict()
        with open(headers_file) as f:
            for i, line in enumerate(f):
                line = line.strip('\n')
                # print('-' + line + '-')
                if line.startswith('HTTP'):
                    header = 'status'
                    value = line
                else:
                    if line == '':
                        headers_list.append(headers)
                        headers = collections.OrderedDict()
                        continue
                    header, value = re.search(r'([\w-]+?):(.+)', line).groups()
                header = header.lower()
                value = value.strip(" \"")
                if header == 'date':
                    value = datetime.datetime(*eut.parsedate(value)[:6])
                headers[header] = value
            f.close()
        return headers_list

    @staticmethod
    def check_whitelist(whitelist, item):
        item = item.strip(' ')
        whitelist = whitelist.strip(' ')
        if whitelist == "":
            return True
        whitelist_items = whitelist.split(',')
        for whitelist_item in whitelist_items:
            whitelist_item = whitelist_item.strip(' ')
            if whitelist_item.lower() in item.lower():
                return True
        return False

    @staticmethod
    def check_blacklist(blacklist, item):
        item = item.strip(' ')
        blacklist = blacklist.strip(' ')
        if blacklist == '':
            return True
        blacklist_items = blacklist.split(',')
        for blacklist_item in blacklist_items:
            if blacklist_item.lower() in item.lower():
                return False
        return True

    @staticmethod
    def parse_mra_file(path):
        context = Et.iterparse(path, events=("start",))
        fields = {}
        for event, elem in context:
            elem_tag = elem.tag.lower()
            elem_value = elem.text
            if isinstance(elem_value, str):
                fields[elem_tag] = elem_value
        return fields

    def list_dir(self, path):
        glob = os.listdir(path)
        files = []
        dirs = []
        for item in glob:
            itempath = path + '/' + item
            if os.path.isdir(itempath):
                dirs.append(itempath)
            else:
                files.append(itempath)
        for dir_item in dirs:
            files.extend(self.list_dir(dir_item))
        return files

    @staticmethod
    def get_local_file_mtime(path):
        return datetime.datetime.fromtimestamp(pathlib.Path(path).stat().st_mtime)


class EntitiesMetadataHelper:
    """Methods for storing data associated to files"""

    def __init__(self, paths_helper, metadata_file):
        self.paths_helper = paths_helper
        self.metadata_filepath = self.paths_helper.get_work_filepath(metadata_file)
        self.config_parser = None

    def get_values(self, uid):
        if self.config_parser is None:
            self._load_metadata()
        uid = uid.replace('[', '').replace(']', '')
        try:
            return self.config_parser[uid]
        except KeyError:
            return None

    def get_value(self, uid, field):
        if self.config_parser is None:
            self._load_metadata()
        uid = uid.replace('[', '').replace(']', '')
        try:
            return self.config_parser[uid][field]
        except KeyError:
            return None

    def get_sections(self):
        if self.config_parser is None:
            self._load_metadata()
        return self.config_parser.sections()

    def get_sections_by_regex(self, regex):
        if self.config_parser is None:
            self._load_metadata()
        regex = re.compile(regex)
        ret = []
        for k in self.config_parser:
            if regex.match(k) is not None:
                ret.append(k)
        return ret

    def get_sections_by_field_regex(self, field, regex):
        regex = re.compile(regex)
        ret = []
        for k in self.config_parser:
            if field not in self.config_parser[k]:
                continue
            if regex.match(self.config_parser[k][field]) is not None:
                ret.append(k)
        return ret

    def delete_sections_by_field_value(self, field, value):
        for k in self.get_sections_by_field_regex(field, value):
            self.config_parser.remove_section(k)

    def _load_metadata(self):
        self.config_parser = configparser.ConfigParser()
        self.config_parser['LAST_EXECUTION'] = {}  # this makes this item go first in the file
        try:
            self.config_parser.read_file(codecs.open(self.metadata_filepath, "r", "utf8"))
        except FileNotFoundError:
            pass

    def _save_metadata(self):
        if self.config_parser is None:
            return
        with open(self.metadata_filepath + '.temp', 'w') as f:
            self.config_parser.write(f)
        os.rename(self.metadata_filepath + '.temp', self.metadata_filepath)

    def _update_value(self, uid, field, value):
        if self.config_parser is None:
            self._load_metadata()
        uid = uid.replace('[', '').replace(']', '')
        if uid not in self.config_parser:
            self.config_parser[uid] = {}
        self.config_parser[uid][field] = str(value).replace('%', '%%')

    def set_value(self, uid, field, value):
        self._update_value(uid, field, value)

    def set_values(self, uid, values):
        for field in values:
            self._update_value(uid, field, values[field])
        self._save_metadata()

    def delete_values(self, uid):
        uid = uid.replace('[', '').replace(']', '')
        self.config_parser.remove_section(uid)

    def save(self):
        self._save_metadata()

    @staticmethod
    def _get_filename(file):
        return os.path.basename(file)


class PathsHelper:

    def __init__(self, config):
        self.config = config

    def check_category_path(self, core_category):
        """Check if core category path is defined"""
        if core_category not in self.config['CATEGORY_PATHS']:
            raise UpdateCoreError("CATEGORY_PATH not defined for category: " + core_category)

    @staticmethod
    def ensure_path_exists(path, delete_first=False):
        if delete_first:
            shutil.rmtree(path, ignore_errors=True)
        if not os.path.isdir(path):
            os.makedirs(path)
        return path

    def ensure_work_path_exists(self, subpath="", delete_first=False):
        if subpath != "":
            subpath = '/' + subpath.lstrip('/')
        return self.ensure_path_exists(self.config['GENERAL']['WORK_PATH'] + subpath, delete_first=delete_first)

    def get_work_filepath(self, remote_file, subpath=""):
        """Given a MRA or RBF URL, provides a path in the work folder for downloading it"""
        if subpath != "":
            subpath = '/' + subpath.lstrip('/')
        file_name = urllib.parse.unquote(os.path.basename(remote_file))
        return self.config['GENERAL']['WORK_PATH'] + subpath + '/' + file_name

    def get_category_files_path(self, core_category, extension=None):
        if extension == 'rbf' and (core_category in ['jotego-cores', 'jotego-beta-cores']):
            core_category = 'arcade-cores'
        path = self.config['CATEGORY_PATHS'][core_category]
        if extension == 'rbf' and core_category == 'arcade-cores':
            path = path + '/cores'
        return path

    def get_local_filepath(self, core_category, remote_file):
        """Given the repo info and the remote file URL, returns the local PATH where the file must be stored"""

        file_name, file_extension = os.path.splitext(os.path.basename(remote_file))
        if file_extension == '.mra':
            return self.get_local_mra_path(core_category, remote_file)
        elif file_extension == '.rbf':
            return self.get_local_rbf_path(core_category, remote_file)
        else:
            return None

    def get_local_mra_path(self, core_category, remote_file):
        """Given the repo info and the remote file URL, returns the local PATH where the MRA must be stored"""

        files_path = self.get_category_files_path(core_category)
        mra_file = urllib.parse.unquote(os.path.basename(remote_file))
        return files_path + '/' + mra_file

    def get_local_alternative_mra_path(self, core_category, temp_relative_path, temp_path):
        """Given the repo info and the downloaded alternative path (relative to ZIP folder), returns the local PATH
        where the MRA must be stored"""
        if temp_relative_path.startswith('/_alternatives'):
            temp_relative_path = temp_relative_path[len('/_alternatives'):]
        files_path = self.get_category_files_path(core_category)
        return files_path + temp_relative_path

    def get_local_rbf_path(self, core_category, remote_file):
        """Given the repo info and the remote file URL, returns the local PATH where the RBF must be stored"""

        # menu is stored in BASE_PATH
        basename = os.path.basename(remote_file)
        if basename.startswith('menu_'):
            return self.config['GENERAL']['BASE_PATH'] + '/' + self.remove_version(basename)

        files_path = self.get_category_files_path(core_category, 'rbf')
        rbf_file = urllib.parse.unquote(os.path.basename(remote_file))
        if self.config.getboolean('MAIN_MISTER', 'REMOVE_ARCADE_PREFIX'):
            rbf_file = rbf_file.replace('Arcade-', '')
        return files_path + '/' + rbf_file

    def group_file_versions(self, files):
        """Given a list of files with versions, returns a dictionary of lists, grouping by same file name"""
        ret = {}
        for file in files:
            key = self.remove_version(file)
            if key not in ret:
                ret[key] = []
            ret[key].append(file)
        return ret

    @staticmethod
    def remove_version(file_name):
        return re.sub(r'_\d{8}[a-z]*', '', file_name)

    def add_version(self, file_name, version):
        file_name = self.remove_version(file_name)
        file_name, file_extension = os.path.splitext(file_name)
        return file_name + '_' + str(version) + file_extension

    @staticmethod
    def replace_version(filename, new_version):
        version = re.search(r'_(\d{8})[a-z]*', filename)
        if version is None:
            return filename
        return filename.replace(version.group(1), new_version)

    def get_max_version(self, files):
        max_version_allowed = self.config['GENERAL']['MAX_VERSION']
        max_version_allowed = None if max_version_allowed == "" else int(max_version_allowed)
        max_version = -1
        max_version_file = None
        for file in files:
            version = self.get_version(file, 0)
            if version > max_version and (max_version_allowed is None or version <= max_version_allowed):
                max_version_file = file
                max_version = version
        return max_version_file

    @staticmethod
    def get_version(file, default=None):
        version = re.search(r'(\d{8})', os.path.basename(file))
        return int(version.group(1)) if version else default

    def get_regex_for_all_file_versions(self, path):
        """Substitutes the actual version of the path, for a regex that matches any version"""

        regex = re.escape(self.replace_version(path, '__REGEX__'))
        return regex.replace('__REGEX__', '\d{8}')


class UpdateSummaryHelper:

    def __init__(self):
        self.updated_files = []
        self.files_not_deleted_by_error = []
        self.deleted_versions = {}
        self.deleted_files = []
        self.start_time = None
        self.end_time = None

    def add_updated_file(self, file):
        self.updated_files.append(file)

    def add_files_not_updated_by_error(self, file):
        self.files_not_deleted_by_error.append(file)

    def add_deleted_file_version(self, file, deleted_file):
        if file not in self.deleted_versions:
            self.deleted_versions[file] = []
        self.deleted_versions[file].append(deleted_file)

    def add_deleted_file(self, file):
        self.deleted_files.append(file)

    def set_starttime(self, start_time):
        self.start_time = start_time

    def set_endtime(self, end_time):
        self.end_time = end_time

    def log_summary(self):
        logger = logging.getLogger('summary')
        logger.info('')
        logger.info('==================================')
        logger.info('Update summary')
        logger.info('Start time: ' + str(self.start_time))
        logger.info('End time  : ' + str(self.end_time))
        logger.info('==================================')
        logger.info('Updated files:')
        if self.updated_files:
            for file in self.updated_files:
                logger.info(' ' + file)
                if file in self.deleted_versions:
                    for deleted_file in self.deleted_versions[file]:
                        if os.path.basename(file) == os.path.basename(deleted_file):
                            logger.info('    |___ deleted version: ' + os.path.basename(deleted_file))
                        else:
                            logger.info('    |___ deleted version from other path: ' + deleted_file)
                    del self.deleted_versions[file]
        else:
            logger.info(' None')
        logger.info('')
        logger.info('Files that could not be updated:')
        if self.files_not_deleted_by_error:
            for file in self.files_not_deleted_by_error:
                logger.info(' ' + file)
        else:
            logger.info(' None')

        logger.info('')
        logger.info('Other files deleted:')
        if self.deleted_files:
            for deleted_file in self.deleted_files:
                logger.info(' ' + deleted_file)
        else:
            logger.info(' None')

        logger.info('')


class LocalFilesHelper:

    def __init__(self, config, paths_helper, system_helper, summary_helper):
        self.config = config
        self.paths_helper = paths_helper
        self.system_helper = system_helper
        self.summary_helper = summary_helper

    def get_category_paths_files_list(self, skipped_files=None):
        """Scans each category path and returns a list of all files present"""
        if skipped_files is None:
            skipped_files = []
        files = []
        cp = self.config['CATEGORY_PATHS']
        # todo: categories with overlapping folders should not be scanned
        for category in cp:
            path = cp[category]
            if os.path.exists(path):
                path_files = self.system_helper.list_dir(path)
                for file in path_files:
                    if file not in files and file not in skipped_files:
                        files.append(file)
        return files

    def delete_files(self, files_not_to_be_deleted):
        all_files = self.get_category_paths_files_list(skipped_files=files_not_to_be_deleted)
        for file in all_files:
            if file in files_not_to_be_deleted:
                continue
            os.unlink(file)
            logging.info('   Deleted file: ' + file)
            self.summary_helper.add_deleted_file(file)


class MainCoresUrlsProvider:
    MISTER_URL = "https://github.com/MiSTer-devel/Main_MiSTer"
    ALTERNATIVES_URL = "https://github.com/MiSTer-devel/MRA-Alternatives_MiSTer"

    def __init__(self, config, system_helper):
        self.config = config
        self.system_helper = system_helper

    def __call__(self):
        return self.fetch_repo_urls()

    def fetch_repo_urls(self):
        """Parses the MiSTer WIKI page and grabs the core URLs, organized by category"""

        logging.debug('')
        logging.debug('Fetching core URLs from Main_MiSTer repo Wiki')

        wiki_url = self.MISTER_URL + '/wiki'
        htm = self.system_helper.execute_curl(wiki_url, append_body=True).body \
            .replace('\n', '')
        htm = re.search(r'user-content-fpga-cores(.*)user-content-development', htm)
        matches = re.findall(r'(https://github.com/[a-zA-Z0-9./_-]*[_-]MiSTer|user-content-[a-zA-Z0-9-]*)',
                             htm.group(0))
        core_category = None
        urls = {}
        for match in matches:
            if 'MRA-Alternatives' in match:
                continue
            if match.startswith('user-content'):
                core_category = self._normalize_core_category(match)
            else:
                # todo remove, only for development
                if core_category == 'other_cores':
                    continue
                if core_category not in urls:
                    urls[core_category] = []
                urls[core_category].append(match)
                # print(core_category + ' ' + match)

        urls['arcade-cores'] = self._get_arcade_core_urls()
        urls['arcade-alternative-cores'] = [self.ALTERNATIVES_URL]
        logging.debug('MainCoresUrlsProvider: Found {} URLs'.format(sum([len(urls[x]) for x in urls])))

        return urls

    @staticmethod
    def _normalize_core_category(html_core_category):
        if 'comput' in html_core_category:
            return 'computer-cores'
        elif 'console' in html_core_category:
            return 'console-cores'
        elif 'other-systems' in html_core_category:
            return 'other-cores'
        else:
            return html_core_category.replace('user-content-', '')

    def _get_arcade_core_urls(self):
        htm = self.system_helper.execute_curl(self.MISTER_URL + '/wiki/Arcade-Cores-List',
                                              append_body=True).body.replace('\n', '')
        htm = re.search(r'wiki-content(.*)wiki-rightbar', htm)
        urls = re.findall(r'(https://github.com/.*?Arcade-[a-zA-Z0-9./_-]*[_-]M[i|I]STer)', htm.group(0))
        return urls


class JotegoCoresUrlsProvider:
    JTBIN_URL = "https://github.com/jotego/jtbin"
    ALTERNATIVES_URL = "https://github.com/jotego/jtbin/tree/master/mister/MRA-Alternatives_MiSTer"
    BETA_CORES = [
        's16', 's16a2', 's16b', 's16b1', 'mx5k', 'flane'
    ]

    def __init__(self, config, paths_helper, system_helper):
        self.config = config
        self.paths_helper = paths_helper
        self.system_helper = system_helper

    def __call__(self):
        return self.fetch_repo_urls()

    def fetch_repo_urls(self):
        """Parses the JTBIN WIKI page and grabs the core URLs"""

        logging.debug('')
        logging.debug('Fetching core URLs from Jotego repo Wiki')

        wiki_url = self.JTBIN_URL + '/wiki'
        htm = self.system_helper.execute_curl(wiki_url, append_body=True).body.replace('\n', '')
        matches = re.findall(r'(https://github.com/jotego/jtbin/tree/master/mister/[a-zA-Z0-9-]*)', htm)
        urls = []
        beta_urls = []
        for match in matches:
            is_beta = len(list(filter(match.endswith, self.BETA_CORES))) > 0
            if is_beta:
                beta_urls.append(match)
            else:
                urls.append(match)
        category_urls = {
            'jotego-cores': urls,
            'jotego-beta-cores': beta_urls,
            'jotego-alternative-cores': [self.ALTERNATIVES_URL],
        }
        logging.debug(
            'JotegoCoresUrlsProvider: Found {} URLs'.format(sum([len(category_urls[x]) for x in category_urls])))

        return category_urls

    def get_local_alternative_mra_path(self, core_category, relative_path, temp_path):
        mra_data = self.system_helper.parse_mra_file(temp_path)
        is_beta = len(list(filter(mra_data['rbf'].endswith, self.BETA_CORES))) > 0
        if is_beta:
            core_category = 'jotego-beta-alternative-cores'
        return self.paths_helper.get_local_alternative_mra_path(core_category, relative_path, temp_path)


class RampaCoresUrlsProvider:
    ZX48_URL = "https://github.com/Kyp069/zx48-MiSTer"

    def __init__(self, config, paths_helper, system_helper):
        self.config = config
        self.paths_helper = paths_helper
        self.system_helper = system_helper

    def __call__(self):
        return {
            'rampa-computer-cores': [
                self.ZX48_URL
            ],
        }


class CoresUpdater:

    def __init__(self, config, paths_helper, system_helper, github_repos_info_helper, summary_helper,
                 local_files_helper, metadata_helper):
        self.config = config
        self.paths_helper = paths_helper
        self.system_helper = system_helper
        self.github_repos_info_helper = github_repos_info_helper
        self.summary_helper = summary_helper
        self.local_files_helper = local_files_helper
        self.metadata_helper = metadata_helper
        self._headers_cache = {}
        self._full_sync_mode = False
        self._current_urls_provider = None

    def update(self, repo_urls_providers):

        self._full_sync_mode = self._should_emable_full_sync_mode()
        if self._full_sync_mode:
            logging.info('   >>> FULL SYNC <<<')

        for repo_urls_provider in repo_urls_providers:

            self._current_urls_provider = repo_urls_provider

            # url providers must be callable (a function or a callable object)
            repo_urls = repo_urls_provider()
            categories = sorted(repo_urls.keys(), key=lambda x: x.lower())
            for core_category in categories:

                if not self.system_helper.check_whitelist(self.config['FILTERS']['CATEGORY_WHITELIST'],
                                                          core_category):
                    logging.debug('   Category not in whitelist. Won\'t update')
                    continue
                if not self.system_helper.check_blacklist(self.config['FILTERS']['CATEGORY_BLACKLIST'],
                                                          core_category):
                    logging.debug('   Category in blacklist. Won\'t update')
                    continue

                try:
                    self.paths_helper.check_category_path(core_category)
                except UpdateCoreError as e:
                    logging.error(e)
                    continue

                is_first_category_core = True

                for repo_url in repo_urls[core_category]:

                    if is_first_category_core:
                        logging.info('')
                        logging.info('### Updating category: {} ###'.format(core_category))
                        is_first_category_core = False

                    logging.debug('Updating cores in: ' + repo_url)
                    if not self.system_helper.check_whitelist(self.config['FILTERS']['CORE_WHITELIST'], repo_url):
                        logging.debug('   Core not in whitelist. Won\'t update')
                        continue
                    if not self.system_helper.check_blacklist(self.config['FILTERS']['CORE_BLACKLIST'], repo_url):
                        logging.debug('   Core in blacklist. Won\'t update')
                        continue

                    try:
                        self._update_repo_files(repo_url, core_category)
                    except Exception as e:
                        logging.error('  @@@@ Error while scanning: ' + repo_url + ' @@@@', exc_info=e)

        self.metadata_helper.set_value('LAST_EXECUTION', 'TIMESTAMP',
                                       datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    def _should_emable_full_sync_mode(self):

        if self.config.getboolean('GENERAL', 'FORCE_UPDATE'):
            logging.info('  Full sync enabled by configuration flag.')
            return True

        last_execution_timestamp = self.metadata_helper.get_value('LAST_EXECUTION', 'TIMESTAMP')
        if last_execution_timestamp is None:
            logging.info('  Last execution timestamp not present in metadata. Force full sync.')
            return True

        last_execution_timestamp = datetime.datetime.strptime(last_execution_timestamp, "%Y-%m-%d %H:%M:%S")
        config_file_timestamp = datetime.datetime.fromtimestamp(int(self.config['GENERAL']['CONFIG_FILE_TIMESTAMP']))
        if config_file_timestamp >= last_execution_timestamp:
            logging.info('  Config file modified since last execution. Force full sync.')
            return True

        return False

    def _update_repo_files(self, repo_url, core_category):

        core_repo_info = self.github_repos_info_helper.get_repo_info(repo_url)
        if core_repo_info is None:
            raise UpdateCoreError('No repo info found for URL: ' + repo_url)

        logging.info('')
        logging.info(' -------- Scanning: ' + repo_url + ' ---------')

        if not self._full_sync_mode:
            last_repo_succesful_update_timestamp = self.metadata_helper.get_value(repo_url, 'checked_at')
            if last_repo_succesful_update_timestamp is not None:
                last_repo_succesful_update_timestamp = datetime.datetime.strptime(last_repo_succesful_update_timestamp,
                                                                                  "%Y-%m-%d %H:%M:%S")
                if last_repo_succesful_update_timestamp > self._get_last_repo_update_timestamp(
                        core_repo_info):
                    logging.debug('   No changes since last repo update.')
                    return

        remote_files = self._fetch_core_files_list(core_category, repo_url, core_repo_info)
        for file in remote_files:
            remote_file = self.paths_helper.get_max_version(remote_files[file])
            if remote_file is None:
                logging.debug('   ' + file)
                logging.debug('   No version found that complies with MAX_VERSION')
                continue
            try:
                if os.path.basename(file) == 'MRA-Alternatives.zip':
                    self._update_remote_alternative_mras(remote_file, core_repo_info, core_category)
                else:
                    extension = os.path.splitext(file)[1].lstrip('.').lower()
                    if extension in ['rbf', 'mra']:
                        self._update_remote_file(remote_file, core_repo_info, core_category)
                if remote_file in self._headers_cache:
                    del self._headers_cache[remote_file]
            except Exception as e:
                logging.error('  @@@@ Error while updating: ' + remote_file + ' @@@@', exc_info=e)
                self.summary_helper.add_files_not_updated_by_error(remote_file)

        self.metadata_helper.set_value(repo_url, 'checked_at', datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    def _fetch_core_files_list(self, core_category, repo_url, core_repo_info):
        """Given a core repo item, parses the releases page and grabs all the file names"""

        releases_url = self.github_repos_info_helper.get_repo_releases_url(repo_url, core_repo_info)
        repo_full_name = core_repo_info['full_name']
        logging.debug('  releases URL: ' + releases_url)
        releases_html = self.system_helper.execute_curl(releases_url, append_body=True).body.replace('\n', '')
        files = re.findall(r'href=[\'"]?' + r'(/' + repo_full_name + r'/[^\'">]+\.(?:rbf|mra|zip))', releases_html)
        files = ['https://github.com' + html.unescape(f) for f in files]
        files = self._fix_remote_files(core_category, repo_url, files)
        return self.paths_helper.group_file_versions(files)

    @staticmethod
    def _fix_remote_files(core_category, repo_url, remote_files):
        if repo_url == "https://github.com/MiSTer-devel/Atari800_MiSTer":
            search_string = 'Atari800' if core_category == 'computer-cores' else 'Atari5200'
            remote_files = filter(lambda url: search_string in os.path.basename(url), remote_files)
        return remote_files

    def _update_remote_file(self, remote_file, core_repo_info, core_category):

        logging.info('')
        logging.info('   Remote file: ' + remote_file)

        local_filepath = self.paths_helper.get_local_filepath(core_category, remote_file)
        if local_filepath is None:
            raise UpdateCoreError

        must_update = not pathlib.Path(local_filepath).exists() or \
                      self._should_update_remote_file(core_repo_info, remote_file)

        if must_update:
            temp_local_filepath = self.paths_helper.get_work_filepath(local_filepath, 'files')
            ex = self.system_helper.execute_curl(self.github_repos_info_helper.get_download_url(remote_file),
                                                 download_path=temp_local_filepath)
            self.paths_helper.ensure_path_exists(os.path.dirname(local_filepath))
            os.rename(temp_local_filepath, local_filepath)
            logging.info('   Downloaded to: ' + local_filepath)
            old_local_filepath = self.metadata_helper.get_value(remote_file, 'local_path')
            if old_local_filepath is not None and old_local_filepath != local_filepath \
                    and pathlib.Path(old_local_filepath).exists():
                os.unlink(old_local_filepath)
                logging.info('   Deleted old path: ' + old_local_filepath)
                self.summary_helper.add_deleted_file_version(remote_file, old_local_filepath)
            http_headers = ex.headers[-1]
            self.metadata_helper.set_values(remote_file, {
                'core_category': core_category,
                'local_path': local_filepath,
                'etag': http_headers['etag'],
                'checked_at': http_headers['date'].strftime("%Y-%m-%d %H:%M:%S"),
            })
            logging.debug('   File metadata updated')
        self._handle_other_file_versions(remote_file, local_filepath)
        self.summary_helper.add_updated_file(local_filepath)

    def _handle_other_file_versions(self, url, local_filepath):
        """Search for other versions of the file (MRA or RBF) in the metadata and delete them"""

        file_versions_regex = self.paths_helper.get_regex_for_all_file_versions(url)
        file_versions = self.metadata_helper.get_sections_by_regex(file_versions_regex)
        for file_url in file_versions:
            if file_url == url:
                continue
            old_version_metadata = self.metadata_helper.get_values(file_url)
            if pathlib.Path(old_version_metadata['local_path']).exists():
                os.unlink(old_version_metadata['local_path'])
                logging.info('   Deleted old version: ' + old_version_metadata['local_path'])
                self.summary_helper.add_deleted_file_version(local_filepath, old_version_metadata['local_path'])
            self.metadata_helper.delete_values(file_url)

    def _update_remote_alternative_mras(self, remote_file, core_repo_info, core_category):

        logging.info('')
        logging.info('   Remote file: ' + remote_file)

        if self._should_update_remote_file(core_repo_info, remote_file):

            mra_files_before_update = self.metadata_helper.get_value(remote_file, 'mra_files')
            if mra_files_before_update is not None:
                mra_files_before_update = mra_files_before_update.split('\n')

            temp_filename = core_repo_info['name'] + '_' + os.path.basename(remote_file)
            temp_filepath = self.paths_helper.get_work_filepath(temp_filename, 'files')
            self.paths_helper.ensure_path_exists(os.path.dirname(temp_filepath))
            ex = self.system_helper.execute_curl(self.github_repos_info_helper.get_download_url(remote_file),
                                                 download_path=temp_filepath)
            http_headers = ex.headers[-1]

            # unzip and move each MRA to destination
            folder_name = os.path.splitext(temp_filename)[0].lstrip('.').lower()
            unzip_temp_folder = self.paths_helper.get_work_filepath(folder_name, 'temp')
            self.paths_helper.ensure_path_exists(unzip_temp_folder, delete_first=True)
            self.system_helper.execute_unzip(temp_filepath, unzip_temp_folder)
            temp_mra_paths = self.system_helper.list_dir(unzip_temp_folder + '/_alternatives')
            mra_files_meta = []
            mra_relative_paths = []
            for temp_mra_path in temp_mra_paths:
                try:
                    if not temp_mra_path.startswith(unzip_temp_folder):
                        raise UpdateCoreError
                    mra_relative_path = temp_mra_path[len(unzip_temp_folder):]
                    local_filepath = self._get_local_alternative_mra_path(core_category, mra_relative_path,
                                                                          temp_mra_path)
                    self.paths_helper.ensure_path_exists(os.path.dirname(local_filepath))
                    os.rename(temp_mra_path, local_filepath)
                    logging.info('   Copied file: ' + local_filepath)
                    mra_files_meta.append(mra_relative_path + '||' + local_filepath)
                    mra_relative_paths.append(mra_relative_path)
                except Exception as e:
                    logging.error('  @@@@ Error while moving: ' + temp_mra_path + ' @@@@', exc_info=e)
                    self.summary_helper.add_files_not_updated_by_error(temp_mra_path)
            shutil.rmtree(unzip_temp_folder)
            os.unlink(temp_filepath)
            self.metadata_helper.set_values(remote_file, {
                'core_category': core_category,
                'etag': http_headers['etag'],
                'checked_at': http_headers['date'].strftime("%Y-%m-%d %H:%M:%S"),
                'mra_files': '\n'.join(mra_files_meta),
            })
            self.summary_helper.add_updated_file(remote_file)

            if mra_files_before_update is not None:
                for mra_file_before_update in mra_files_before_update:
                    mra_file_before_update_relative_path, mra_file_before_update_path = mra_file_before_update.split(
                        '||')
                    if mra_file_before_update_relative_path not in mra_relative_paths:
                        if pathlib.Path(mra_file_before_update_path).exists():
                            os.unlink(mra_file_before_update_path)
                            self.summary_helper.add_deleted_file_version(mra_file_before_update_path)
                        logging.info('   Deleted file missing from new ZIP version:' + mra_file_before_update_path)

        # self._handle_other_alternatives_zip_versions(core_category, remote_file, mra_files)

    # todo check
    def _handle_other_alternatives_zip_versions(self, core_category, url, current_mra_files):
        file_versions_regex = self.paths_helper.get_regex_for_all_file_versions(url)
        file_versions = self.metadata_helper.get_sections_by_regex(file_versions_regex)
        for file_url in file_versions:
            if file_url == url:
                continue
            mra_files = self.metadata_helper.get_value(file_url, 'mra_files').split('\n')
            for mra_file in mra_files:
                mra_file_before_update_relative_path, mra_file_before_update_path = mra_file_before_update.split('||')
                if mra_file not in current_mra_files:
                    local_filepath = self.paths_helper.get_local_alternative_mra_path(core_category, mra_file)
                    if pathlib.Path(local_filepath).exists():
                        os.unlink(local_filepath)
                    logging.info('   Deleted file from older version:' + local_filepath)
            self.metadata_helper.delete_values(file_url)
            logging.info('   Deleted old version: ' + file_url)

    def _get_local_alternative_mra_path(self, core_category, relative_path, temp_path):
        try:
            return self._current_urls_provider.get_local_alternative_mra_path(core_category, relative_path, temp_path)
        except AttributeError:
            return self.paths_helper.get_local_alternative_mra_path(core_category, relative_path, temp_path)

    def _should_update_remote_file(self, core_repo_info, remote_file):

        if self._full_sync_mode:
            return True

        remote_file_metadata = self.metadata_helper.get_values(remote_file)
        if remote_file_metadata is None:
            logging.debug('   File metadata not present.')
            return True

        local_file_timestamp = remote_file_metadata['checked_at']
        if local_file_timestamp is not None:
            local_file_timestamp = datetime.datetime.strptime(local_file_timestamp, "%Y-%m-%d %H:%M:%S")
        logging.debug('   Local file timestamp: ' + str(local_file_timestamp))

        # Check last repo modification time so we don't have to check remote file
        last_repo_update = self._get_last_repo_update_timestamp(core_repo_info)
        logging.debug('   Last repo update: ' + str(last_repo_update))
        if local_file_timestamp is not None and local_file_timestamp > last_repo_update:
            logging.debug('   Local file present and newer than last repo update.')
            return False

        # Check the HTTP ETAG.
        local_etag = self.metadata_helper.get_value(remote_file, 'etag')
        if local_etag is None:
            logging.debug('   No ETAG metadata for local file. Will update.')
            return True
        logging.debug('   Local file ETAG:  ' + local_etag)

        remote_etag = self._fetch_headers(remote_file)[-1]['etag']
        logging.debug('   Remote file ETAG: ' + remote_etag)

        if local_etag == remote_etag:
            logging.debug('   Local and remote ETAG match.')
            return False
        else:
            logging.debug('   Local and remote ETAG don\'t match.')
            return True

    def _fetch_headers(self, url):
        if url not in self._headers_cache:
            self._headers_cache[url] = self.system_helper.execute_curl(self.github_repos_info_helper.
                                                                       get_download_url(url)).headers
        return self._headers_cache[url]

    @staticmethod
    def _get_last_repo_update_timestamp(core_repo_info):
        return datetime.datetime.strptime(core_repo_info['updated_at'], "%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def _get_core_metadata_uid(local_filepath):
        return os.path.basename(local_filepath)

    def get_local_files_list(self):
        local_files = []
        for url in self.metadata_helper.get_sections():
            values = self.metadata_helper.get_values(url)
            if 'local_path' in values:
                local_files.append(values['local_path'])
            elif 'mra_files' in values:
                for mra_file_info in values['mra_files'].split('\n'):
                    relative_path, full_path = mra_file_info.split('||')
                    local_files.append(full_path)
        return local_files


class TestCoresUpdater(CoresUpdater):

    def _download_file(self, remote_file, local_filepath):
        self.paths_helper.ensure_path_exists(os.path.dirname(local_filepath))
        pathlib.Path(local_filepath).touch(exist_ok=True)
        self.metadata_helper.set_values(remote_file, {
            'remote_file': remote_file,
            'etag': 'TEST_ETAG',
            'checked_at': self.system_helper.get_local_file_mtime(local_filepath).strftime("%Y-%m-%d %H:%M:%S")
        })


def setup_logging(level, log_file_path):
    logger = logging.getLogger("")
    logger.setLevel(level)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s]: %(message)s')
    file_handler = logging.handlers.RotatingFileHandler(log_file_path, maxBytes=(1024*1024), backupCount=0)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

def setup_summary_logging(log_file_path):
    logger = logging.getLogger("summary")
    logger.setLevel('INFO')
    formatter = logging.Formatter('%(message)s')
    file_handler = logging.handlers.RotatingFileHandler(log_file_path, maxBytes=(1024*1024), backupCount=0)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

def load_config(config_filepath):
    config_parser = configparser.ConfigParser()
    config_parser._interpolation = configparser.ExtendedInterpolation()
    config_parser.read_file(codecs.open(config_filepath, "r", "utf8"))
    config_file_timestamp = datetime.datetime.fromtimestamp(pathlib.Path(config_filepath).stat().st_mtime)
    config_file_timestamp = os.path.getmtime(config_filepath)
    config_parser['GENERAL']['CONFIG_FILE_TIMESTAMP'] = str(int(config_file_timestamp))
    return config_parser


def run():

    config_file = 'update_cores.ini'
    config = load_config(config_file)

    # initialize dependencies
    paths_helper = PathsHelper(config)
    system_helper = SystemHelper(config, paths_helper)
    cache_helper = CacheHelper(config, paths_helper)
    github_repos_info_helper = GithubReposInfoHelper(config, paths_helper, system_helper, cache_helper)
    update_summary_helper = UpdateSummaryHelper()
    update_summary_helper.set_starttime(datetime.datetime.now())
    local_files_helper = LocalFilesHelper(config, paths_helper, system_helper, update_summary_helper)

    paths_helper.ensure_work_path_exists('logs')
    log_file_path = paths_helper.get_work_filepath('update_cores.log', 'logs')
    setup_logging(config['GENERAL']['LOG_LEVEL'], log_file_path)

    try:

        logging.info('*********************************************')
        logging.info("**** STARTING MISTER CORES UPDATE SCRIPT ****")
        logging.info('*********************************************')
        logging.info('')

        # setup
        paths_helper.ensure_work_path_exists()
        system_helper.check_certificates()

        # initialize core repos URLs providers
        repo_urls_providers = []
        repo_urls_providers.append(MainCoresUrlsProvider(config, system_helper))
        repo_urls_providers.append(JotegoCoresUrlsProvider(config, paths_helper, system_helper))
        repo_urls_providers.append(RampaCoresUrlsProvider(config, paths_helper, system_helper))

        # update the cores
        metadata_helper = EntitiesMetadataHelper(paths_helper, 'metadata.ini')
        cores_updater = CoresUpdater(config, paths_helper, system_helper, github_repos_info_helper,
                                     update_summary_helper, local_files_helper, metadata_helper)
        cores_updater.update(repo_urls_providers)
        # local_files_helper.delete_files(cores_updater.get_local_files_list())

        logging.info('')
        logging.info('***** MISTER CORES UPDATE FINISHED *****')
        logging.info('')

    except Exception as e:
        logging.critical("Uncaught exception. Exiting script", exc_info=e)
        logging.critical("Uncaught exception: " + str(e))
    except KeyboardInterrupt:
        logging.info("Script stopped. Exiting")

    logging.info('Saving files metadata.ini')
    metadata_helper.save()

    try:
        update_summary_helper.set_endtime(datetime.datetime.now())
        log_file_path = paths_helper.get_work_filepath('summary.log', 'logs')
        setup_summary_logging(log_file_path)
        update_summary_helper.log_summary()
    except NameError:
        pass


if __name__ == '__main__':
    run()
