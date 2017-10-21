# -*- coding: utf-8 -*-
import logging

from fuglu.shared import ScannerPlugin, DUNNO,string_to_actioncode,apply_template


class URIExtractAddHeader(ScannerPlugin):
    def __init__(self, config, section=None):
        ScannerPlugin.__init__(self, config, section)
        self.logger = logging.getLogger('fuglu.plugin.DomainAction')

        self.requiredvars = {
            'addheaderlinks': {
                'default': 0,
                'description': 'Add header with blacklisted uris',
            },
            'addheadercount': {
                'default': 0,
                'description': 'Add header with count of blacklisted uris',
            },
            'action': {
                'default': 'DUNNO',
                'description': 'action on hit (reject, delete, etc)',
            },
            'message': {
                'default': '5.7.1 black listed URL ${domain} by ${blacklist}',
                'description': 'message template for rejects/ok messages',
            }
        }

    def examine(self, suspect):
        urls = suspect.get_tag('black.uris', defaultvalue=[])
        add_header_links = self.config.getboolean(self.section, 'addheaderlinks')
        add_header_count = self.config.getboolean(self.section, 'addheadercount')
        if len(urls) == 0:
            return DUNNO
        elif add_header_count is True and add_header_links is False:
            suspect.add_header('X-Black-Host-Count', str(len(urls)), immediate=True)
        elif add_header_count is True and add_header_links is True:
            suspect.add_header('X-Black-Host', "\t" + "\r\n\t\t\t  ".join(urls), immediate=True)
            suspect.add_header('X-Black-Host-Count', str(len(urls)), immediate=True)
        elif add_header_count is False and add_header_links is True:
            suspect.add_header('X-Black-Host', "\t" + "\r\n\t\t\t  ".join(urls), immediate=True)
        return string_to_actioncode(self.config.get('URIExtractPlugin', 'action'), self.config), apply_template(
            self.config.get('URIExtractPlugin', 'message'), suspect, dict(domain=urls[0], blacklist='tbd'))


class AttachmentAddHeader(ScannerPlugin):
    def __init__(self, config, section=None):
        ScannerPlugin.__init__(self, config, section)
        self.logger = logging.getLogger('fuglu.plugin.DomainAction')

        self.requiredvars = {
             'blockedaddheader': {
                'default': '0',
                'description': 'if set to non zero value a header will be added for blocked files and the message will be accepted\n1:\tonly filename appended as header\n2:\tfilename and details will be added as header\nany other string value will be added as-it-is to header',
            }
        }

    def examine(self, suspect):
        filename = suspect.get_tag('block.file', defaultvalue=[])
        add_header = self.config.get('FiletypePlugin', 'blockedaddheader')
        if len(filename) == 0 or add_header == '0':
            return DUNNO
        elif add_header == '1':
            suspect.add_header('X-Fuglu-Blocked', str(filename['ascii']), immediate=True)
        elif add_header == '2':
            suspect.add_header('X-Fuglu-Blocked', str(filename['info']), immediate=True)
        else:
            suspect.add_header('X-Fuglu-Blocked', str(add_header), immediate=True)
        return DUNNO
#        return string_to_actioncode(self.config.get('URIExtractPlugin', 'action'), self.config), apply_template(
#            self.config.get('URIExtractPlugin', 'message'), suspect, dict(domain=urls[0], blacklist='tbd'))

class ClamAddHeader(ScannerPlugin):
    def __init__(self, config, section=None):
        ScannerPlugin.__init__(self, config, section)
        self.logger = logging.getLogger('fuglu.plugin.DomainAction')

        self.requiredvars = {
             'addheaderinfected': {
                'default': '0',
                'description': 'if set to non zero value a header will be added for infected files\n1:\tonly virusname appended as header\n2:\tvirusname and details will be added as header\nany other string value will be added as-it-is to header',
            },
            'addheaderclean': {
                'default': '0',
                'description': 'add header if message is clean\nany string value will be used as-it-is',
            }
        }

    def examine(self, suspect):
        virusname = suspect.get_tag('clam.virus', defaultvalue=[])
        add_header = self.config.get('ClamavPlugin', 'addheaderinfected')
        if len(virusname) == 0 or add_header == '0':
            return DUNNO
        elif add_header == '1' or add_header == '2':
            suspect.add_header('X-Fuglu-ClamAV', str(virusname), immediate=True)
        else:
            suspect.add_header('X-Fuglu-ClamAV', str(add_header), immediate=True)
        return DUNNO

class FprotAddHeader(ScannerPlugin):
    def __init__(self, config, section=None):
        ScannerPlugin.__init__(self, config, section)
        self.logger = logging.getLogger('fuglu.plugin.DomainAction')

        self.requiredvars = {
            'addheaderinfected': {
                'default': '0',
                'description': 'if set to non zero value a header will be added for infected files\n1:\tonly virusname appended as header\n2:\tvirusname and details will be added as header\nany other string value will be added as-it-is to header',
            },
            'addheaderclean': {
                'default': '0',
                'description': 'add header if message is clean\nany string value will be used as-it-is',
            }
        }

    def examine(self, suspect):
        virusname = suspect.get_tag('fprot.virus', defaultvalue=[])
        add_header = self.config.get('FprotPlugin', 'addheaderinfected')
        if len(virusname) == 0 or add_header == '0':
            return DUNNO
        elif add_header == '1' or add_header == '2':
            suspect.add_header('X-Fuglu-Fprot', str(virusname), immediate=True)
        else:
            suspect.add_header('X-Fuglu-Fprot', str(add_header), immediate=True)
        return DUNNO

class SsspAddHeader(ScannerPlugin):
    def __init__(self, config, section=None):
        ScannerPlugin.__init__(self, config, section)
        self.logger = logging.getLogger('fuglu.plugin.DomainAction')

        self.requiredvars = {
            'addheaderinfected': {
                'default': '0',
                'description': 'if set to non zero value a header will be added for infected files\n1:\tonly virusname appended as header\n2:\tvirusname and details will be added as header\nany other string value will be added as-it-is to header',
            },
            'addheaderclean': {
                'default': '0',
                'description': 'add header if message is clean\nany string value will be used as-it-is',
            }
        }

    def examine(self, suspect):
        virusname = suspect.get_tag('sssp.virus', defaultvalue=[])
        add_header = self.config.get('SSSPPlugin', 'addheaderinfected')
        if len(virusname) == 0 or add_header == '0':
            return DUNNO
        elif add_header == '1' or add_header == '2':
            suspect.add_header('X-Fuglu-Sophos', str(virusname), immediate=True)
        else:
            suspect.add_header('X-Fuglu-Sophos', str(add_header), immediate=True)
        return DUNNO