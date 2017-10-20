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
        add_links = self.config.getboolean(self.section, 'addheaderlinks')
        add_count = self.config.getboolean(self.section, 'addheadercount')
        if len(urls) == 0:
            return DUNNO
        elif add_count is True and add_links is False:
            suspect.add_header('X-Black-Host-Count', str(len(urls)), immediate=True)
        elif add_count is True and add_links is True:
            suspect.add_header('X-Black-Host', "\t" + "\r\n\t\t\t  ".join(urls), immediate=True)
            suspect.add_header('X-Black-Host-Count', str(len(urls)), immediate=True)
        elif add_count is False and add_links is True:
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
        urls = suspect.get_tag('block.file', defaultvalue=[])
        add_links = self.config.get('FiletypePlugin', 'blockedaddheader')
        if len(urls) == 0 or add_links == '0':
            return DUNNO
        elif add_links == '1':
            suspect.add_header('X-Fuglu-Blocked', str(urls['ascii']), immediate=True)
        elif add_links == '2':
            suspect.add_header('X-Fuglu-Blocked', str(urls['info']), immediate=True)
        else:
            suspect.add_header('X-Fuglu-Blocked', str(add_links), immediate=True)
        return DUNNO
#        return string_to_actioncode(self.config.get('URIExtractPlugin', 'action'), self.config), apply_template(
#            self.config.get('URIExtractPlugin', 'message'), suspect, dict(domain=urls[0], blacklist='tbd'))
