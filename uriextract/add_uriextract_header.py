# -*- coding: utf-8 -*-
import logging

from fuglu.shared import ScannerPlugin, DUNNO


class URIExtractAddHeader(ScannerPlugin):
    def __init__(self, config, section=None):
        ScannerPlugin.__init__(self, config, section)
        self.logger = logging.getLogger('fuglu.plugin.DomainAction')

        self.requiredvars = {
            'addheaderlinks': {
                'default': '0',
                'description': 'Add header with blacklisted uris',
            },
            'addheadercount': {
                'default': '0',
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
        add_links = self.config.get(self.section, 'addheaderlinks')
        add_count = self.config.get(self.section, 'addheadercount')
        if len(urls) == 0:
            return DUNNO
        elif add_count == 1 and add_links == 0:
            suspect.add_header('X-Black-Host-Count', str(len(urls)), immediate=True)
        elif add_count == 1 and add_links == 1:
            suspect.add_header('X-Black-Host', "\t" + "\r\n\t\t\t  ".join(urls), immediate=True)
            suspect.add_header('X-Black-Host-Count', str(len(urls)), immediate=True)
        elif add_count == 0 and add_links == 1:
            suspect.add_header('X-Black-Host', "\t" + "\r\n\t\t\t  ".join(urls), immediate=True)
        return string_to_actioncode(self.config.get('URIExtractPlugin', 'action'), self.config), apply_template(
            self.config.get('URIExtractPlugin', 'message'), suspect, dict(domain=urls[0], blacklist='tbd'))
